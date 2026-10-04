//! Two peers behind a localhost test server, and the helpers their path tests share.
#![allow(dead_code)]

#[cfg(all(test, feature = "localhost-testing"))]
pub mod pair {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::remote_ext::results::PeerConnectSuccess;
    use citadel_sdk::test_common::{server_info, wait_for_peers, TestBarrier};
    use futures::future::BoxFuture;
    use futures::stream::FuturesUnordered;
    use futures::{StreamExt, TryStreamExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    pub type Peer = Arc<
        dyn Fn(usize, PeerConnectSuccess<StackedRatchet>) -> BoxFuture<'static, ()> + Send + Sync,
    >;

    /// Runs two peers behind a test server; `peer` gets each side's connection as it arrives.
    pub async fn run_pair(turn: Option<TurnRelayConfig>, udp_mode: UdpMode, peer: Peer) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let finished = Arc::new(AtomicUsize::new(0));
        let (server, server_addr) = server_info::<StackedRatchet>();
        let uuids = [Uuid::new_v4(), Uuid::new_v4()];
        let kernels = FuturesUnordered::new();
        for me in 0..2 {
            let mut setup = PeerConnectionSetupAggregator::default()
                .with_peer_custom(uuids[1 - me])
                .ensure_registered()
                .with_udp_mode(udp_mode);
            if let Some(turn) = turn.clone() {
                setup = setup.with_turn_config(turn);
            }
            let settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuids[me])
                    .build()
                    .unwrap();
            let peer = peer.clone();
            let finished = finished.clone();
            let kernel = PeerConnectionKernel::new(
                settings,
                setup.add(),
                move |mut results, remote| async move {
                    let conn = results.recv().await.unwrap().unwrap();
                    peer(me, conn).await;
                    finished.fetch_add(1, Ordering::SeqCst);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            );
            let client = DefaultNodeBuilder::default().build(kernel).unwrap();
            kernels.push(async move { client.await.map(|_| ()) });
        }
        let clients = Box::pin(async move { kernels.try_collect::<()>().await.map(|_| ()) });
        // A hang guard for the whole pair, not a latency assertion.
        let result = tokio::time::timeout(
            Duration::from_secs(150),
            futures::future::try_select(server, clients),
        )
        .await;
        assert!(result.expect("test timed out").is_ok());
        assert_eq!(finished.load(Ordering::SeqCst), 2);
    }

    pub fn data(seq: u32) -> Vec<u8> {
        let mut out = vec![0u8];
        out.extend_from_slice(&seq.to_be_bytes());
        out
    }

    pub fn end(total: u32) -> Vec<u8> {
        let mut out = vec![1u8];
        out.extend_from_slice(&total.to_be_bytes());
        out
    }

    /// Reads a stream written with [`data`]/[`end`]: every sequence number exactly once, in order.
    pub async fn receive_in_order(rx: &mut PeerChannelRecvHalf<StackedRatchet>, who: usize) -> u32 {
        let mut next = 0u32;
        loop {
            let msg = rx.next().await.expect("channel closed mid-stream");
            let bytes = msg.as_ref();
            let n = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
            match bytes[0] {
                0 => {
                    assert_eq!(n, next, "peer {who}: message out of order or duplicated");
                    next += 1;
                }
                _ => {
                    assert_eq!(
                        n, next,
                        "peer {who}: messages missing before the end marker"
                    );
                    return next;
                }
            }
        }
    }

    /// A TURN relay that silently drops every packet: the direct attempt is skipped (relay-only)
    /// and the relay attempt runs until it gives up, so the campaign is still running when the
    /// application gets its channel and then fails.
    pub fn black_hole_relay() -> TurnRelayConfig {
        TurnRelayConfig::new(
            vec![TurnServerCredential::new(
                "turn:192.0.2.1:3478?transport=udp",
                "user",
                "pass",
                None,
            )
            .unwrap()],
            TurnPolicy::RelayOnly,
        )
    }

    /// Cuts a UDP path at the OS level: every descriptor in this process bound to `addr`'s port
    /// is atomically replaced (`dup2`) by a fresh, unregistered socket on another port. The owner
    /// keeps its descriptor number but nothing arrives on it again, and what it sends leaves from
    /// a port nobody knows, which is what a dead network path looks like from both ends. Returns
    /// how many descriptors were replaced.
    #[cfg(unix)]
    pub fn kill_udp_socket(addr: std::net::SocketAddr) -> usize {
        use std::mem::{size_of, zeroed};
        let family = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let max_fd = unsafe {
            let mut limit: libc::rlimit = zeroed();
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                (limit.rlim_cur as i64).min(65_536) as i32
            } else {
                4096
            }
        };
        let mut replaced = 0;
        for fd in 0..max_fd {
            // SAFETY: getsockname/getsockopt only write into the buffers passed with their sizes;
            // an fd that is not a socket (or not open) makes them fail, and it is skipped.
            let bound_here = unsafe {
                let mut storage: libc::sockaddr_storage = zeroed();
                let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                if libc::getsockname(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len)
                    != 0
                    || storage.ss_family as i32 != family
                {
                    continue;
                }
                let mut kind: libc::c_int = 0;
                let mut kind_len = size_of::<libc::c_int>() as libc::socklen_t;
                if libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    &mut kind as *mut _ as *mut libc::c_void,
                    &mut kind_len,
                ) != 0
                    || kind != libc::SOCK_DGRAM
                {
                    continue;
                }
                let port = if family == libc::AF_INET {
                    (*(&storage as *const _ as *const libc::sockaddr_in)).sin_port
                } else {
                    (*(&storage as *const _ as *const libc::sockaddr_in6)).sin6_port
                };
                u16::from_be(port) == addr.port()
            };
            if !bound_here {
                continue;
            }
            let bind_to = std::net::SocketAddr::new(addr.ip(), 0);
            let replacement = std::net::UdpSocket::bind(bind_to).expect("replacement socket");
            replacement.set_nonblocking(true).unwrap();
            use std::os::fd::AsRawFd;
            // SAFETY: `fd` is an open socket in this process; dup2 atomically points it at the
            // replacement, and `replacement` is closed on drop, leaving `fd` its only reference.
            assert!(unsafe { libc::dup2(replacement.as_raw_fd(), fd) } == fd);
            replaced += 1;
        }
        replaced
    }
}
