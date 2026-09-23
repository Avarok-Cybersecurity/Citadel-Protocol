//! The relay rendezvous mechanics behind [`super::turn_p2p`]: choosing a TURN server, the
//! candidate IPs a relay permission must cover, and the nonce probe that tells the allocating peer
//! the dialer's exact relay-facing address while opening the dialer's NAT toward the relay.

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use citadel_io::tokio::net::UdpSocket;
use citadel_wire::exports::tokio_rustls::rustls;
use citadel_wire::udp_traversal::turn_relay::{
    reflexive_address, TurnAllocation, TurnRelayConfig, TurnTransport,
};

use crate::proto::peer::p2p_conn_handler::generic_error;

const PROBE_INTERVAL: Duration = Duration::from_millis(100);
pub(super) const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// A dialer whose plain-UDP probes go unanswered this long falls back to its own relay.
pub(super) const UDP_PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const REFLEXIVE_TIMEOUT: Duration = Duration::from_millis(1500);
/// Both start with a zero byte, which QUIC's fixed bit rules out, so a stray one reaching quinn
/// after the hand-over is discarded as a non-QUIC packet.
const PROBE_MAGIC: &[u8; 5] = b"\0CTRP";
const ACK_MAGIC: &[u8; 5] = b"\0CTRA";

fn tagged(magic: &[u8; 5], nonce: &[u8; 16]) -> Vec<u8> {
    [&magic[..], &nonce[..]].concat()
}

/// `stream_first`: try TCP/TLS servers before UDP ones — for a peer that has seen its UDP fail.
pub(super) async fn allocate_first_usable(
    config: &TurnRelayConfig,
    tls: Arc<rustls::ClientConfig>,
    stream_first: bool,
) -> io::Result<TurnAllocation> {
    let mut last_err = generic_error("no TURN server with unexpired credentials");
    let mut servers: Vec<_> = config.usable_servers(SystemTime::now()).collect();
    if stream_first {
        servers.sort_by_key(|s| s.url.transport == TurnTransport::Udp);
    }
    for server in servers {
        match TurnAllocation::allocate(server, Some(tls.clone())).await {
            Ok(a) => return Ok(a),
            Err(err) => {
                log::warn!(target: "citadel", "[TURN] allocation via {}:{} failed: {err}", server.url.host, server.url.port);
                last_err = err;
            }
        }
    }
    Err(last_err)
}

pub(super) fn unspecified_like(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    }
}

/// Deduplicated IPs of the relayed address's family (IPv4-mapped IPv6 folded to IPv4).
pub(super) fn permission_candidates(
    relayed: SocketAddr,
    ips: impl Iterator<Item = IpAddr>,
) -> Vec<IpAddr> {
    ips.map(|ip| match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    })
    .filter(|ip| ip.is_ipv4() == relayed.is_ipv4() && !ip.is_unspecified())
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

/// One CreatePermission per candidate: a server may refuse some addresses (Cloudflare answers 403
/// for private and loopback peers, RFC 8656 §9.1), and one refusal must not void the rest.
pub(super) async fn install_permissions(
    allocation: &TurnAllocation,
    ips: &[IpAddr],
) -> io::Result<()> {
    let mut installed = 0usize;
    let mut last_err = generic_error("no permission candidates");
    for ip in ips {
        match allocation.create_permissions(&[*ip]).await {
            Ok(()) => installed += 1,
            Err(err) => {
                log::debug!(target: "citadel", "[TURN] permission for a dialer candidate refused: {err}");
                last_err = err;
            }
        }
    }
    if installed == 0 {
        return Err(last_err);
    }
    Ok(())
}

/// Where the relay may see this socket's traffic come from: the route's source IP (same host or
/// LAN as the relay) and the socket's server-reflexive IP from this peer's own UDP TURN servers.
///
/// The flag reports whether UDP demonstrably works from this socket (a STUN Binding to one of
/// those servers was answered). A peer with no UDP TURN server, or none answering, treats its
/// UDP as blocked and relays through its own allocation instead.
pub(super) async fn dialer_candidates(
    socket: &UdpSocket,
    relayed: SocketAddr,
    config: &TurnRelayConfig,
) -> (Vec<IpAddr>, bool) {
    let mut out = Vec::new();
    // connect() on a UDP socket only resolves the route; nothing is sent.
    if let Ok(route) = std::net::UdpSocket::bind(unspecified_like(relayed)) {
        if let Ok(local) = route.connect(relayed).and_then(|_| route.local_addr()) {
            out.push(local.ip());
        }
    }
    let udp_servers = config
        .usable_servers(SystemTime::now())
        .filter(|s| s.url.transport == TurnTransport::Udp);
    for server in udp_servers {
        let Ok(mut addrs) =
            citadel_io::tokio::net::lookup_host((server.url.host.as_str(), server.url.port)).await
        else {
            continue;
        };
        let Some(addr) = addrs.find(|a| a.is_ipv4() == relayed.is_ipv4()) else {
            continue;
        };
        if let Ok(reflexive) = reflexive_address(socket, addr, REFLEXIVE_TIMEOUT).await {
            out.push(reflexive.ip());
            return (out, true);
        }
    }
    (out, false)
}

/// Allocator side: answers every nonce-bearing probe (binding a channel to its source) until
/// `acked` — the dialer's next message over the signalling stream — resolves. Returns the
/// dialer's address as the relay saw it (if any probe arrived) with that message.
pub(super) async fn await_probe<T>(
    allocation: &TurnAllocation,
    nonce: &[u8; 16],
    acked: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<(Option<SocketAddr>, T)> {
    let probe = tagged(PROBE_MAGIC, nonce);
    let ack = tagged(ACK_MAGIC, nonce);
    let mut dialer = None;
    let mut acked = std::pin::pin!(acked);
    citadel_io::time::timeout(PROBE_TIMEOUT, async {
        loop {
            citadel_io::tokio::select! {
                done = &mut acked => return Ok((dialer, done?)),
                datagram = allocation.recv_from() => {
                    let (from, payload) = datagram?;
                    if payload != probe {
                        continue;
                    }
                    allocation.bind_channel(from).await?;
                    dialer = Some(from);
                    allocation.send_to(from, &ack)?;
                }
            }
        }
    })
    .await
    .map_err(|_| generic_error("dialer's probes never reached the relay"))?
}

/// How the dialer reaches the allocator's relayed address.
pub(super) enum ProbeLeg<'a> {
    /// Plain UDP from the dialer's socket.
    Udp(&'a UdpSocket),
    /// Through the dialer's own allocation (relay-to-relay).
    OwnRelay(&'a TurnAllocation),
}

impl ProbeLeg<'_> {
    async fn send_to(&self, payload: &[u8], to: SocketAddr) -> io::Result<()> {
        match self {
            ProbeLeg::Udp(socket) => socket.send_to(payload, to).await.map(|_| ()),
            ProbeLeg::OwnRelay(allocation) => allocation.send_to(to, payload),
        }
    }

    async fn recv_from(&self) -> io::Result<(SocketAddr, Vec<u8>)> {
        match self {
            ProbeLeg::Udp(socket) => {
                let mut buf = [0u8; 64];
                let (n, from) = socket.recv_from(&mut buf).await?;
                Ok((from, buf[..n].to_vec()))
            }
            ProbeLeg::OwnRelay(allocation) => allocation.recv_from().await,
        }
    }
}

/// Dialer side: probes `relayed` until the allocator's ack comes back from it, or `within` passes.
pub(super) async fn probe_until_acked(
    leg: ProbeLeg<'_>,
    relayed: SocketAddr,
    nonce: &[u8; 16],
    within: Duration,
) -> io::Result<()> {
    let probe = tagged(PROBE_MAGIC, nonce);
    let ack = tagged(ACK_MAGIC, nonce);
    citadel_io::time::timeout(within, async {
        loop {
            leg.send_to(&probe, relayed).await?;
            let wait = citadel_io::time::timeout(PROBE_INTERVAL, leg.recv_from());
            if let Ok(Ok((from, payload))) = wait.await {
                if from == relayed && payload == ack {
                    return Ok::<(), io::Error>(());
                }
            }
        }
    })
    .await
    .map_err(|_| generic_error("relay never acknowledged the probes"))?
}
