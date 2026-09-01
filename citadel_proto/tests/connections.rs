#[cfg(test)]
pub mod tests {
    use bytes::BytesMut;
    use citadel_io::tokio;
    use citadel_io::ProtocolIO;
    use citadel_proto::prelude::*;
    use citadel_proto::re_imports::NativeClientConfig;
    use citadel_wire::socket_helpers::is_ipv6_enabled;
    use futures::stream::FuturesUnordered;
    use futures::StreamExt;
    use futures::TryStreamExt;
    use rstest::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// The conditions under which a connection case cannot run belong in ONE
    /// place. They were duplicated, and the copies had drifted: the Windows
    /// IPv6/QUIC skip existed in `test_tcp_or_tls` only, so
    /// `test_many_proto_conns` went on binding `[::1]:0` on Windows.
    fn unsupported_here(addr: SocketAddr) -> Option<&'static str> {
        if !cfg!(feature = "multi-threaded") {
            return Some("only works in multi-threaded mode");
        }
        if addr.is_ipv6() && !is_ipv6_enabled() {
            return Some("ipv6 is not enabled locally");
        }
        // Windows IPv6 sockets in dual-stack mode make Quinn fail QUIC endpoint
        // creation with WSAEINVAL (10022).
        if addr.is_ipv6() && cfg!(windows) {
            return Some("windows dual-stack ipv6 breaks QUIC endpoint creation");
        }
        None
    }

    /// Windows denies an ephemeral bind with WSAEACCES (10013) when the port the
    /// OS happened to hand out lies inside a Hyper-V/WinNAT reserved range. The
    /// denial is a property of that one port, not of the address, so asking the
    /// OS for a different port is the correct response — a fresh `:0` bind draws
    /// a new one.
    ///
    /// Deliberately narrow: it retries ONLY WSAEACCES, and ONLY when we asked for
    /// an ephemeral port. A denial on an explicit port is a real configuration
    /// error and is returned untouched, as is every other errno.
    async fn bind_retrying_reserved_ports(
        proto: ServerMode<NativeIO>,
        addr: SocketAddr,
    ) -> std::io::Result<(<NativeIO as ProtocolIO>::Listener, SocketAddr)> {
        const ATTEMPTS: usize = 8;
        const WSAEACCES: i32 = 10013;
        for attempt in 1..=ATTEMPTS {
            match NativeIO::bind(proto.clone(), addr).await {
                Ok(bound) => return Ok(bound),
                Err(e) if addr.port() == 0 && e.raw_os_error() == Some(WSAEACCES) => {
                    log::warn!(target: "citadel", "bind {addr} denied (WSAEACCES) on attempt {attempt}/{ATTEMPTS}: the OS-chosen port is reserved; drawing another");
                }
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{ATTEMPTS} consecutive ephemeral ports for {addr} were reserved"),
        ))
    }

    /// A bind failure must arrive with its errno and kind intact. These were
    /// destroyed by `err.to_string()` conversions, so every failure read as
    /// `ConnectionRefused` — a kind a bind cannot produce — and the errno
    /// survived only as English inside the message. The retry that keeps Windows
    /// CI green depends on reading the errno, and was inert until this held.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn bind_failure_preserves_errno_and_kind() {
        citadel_logging::setup_log();
        let occupant = citadel_io::tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let taken = occupant.local_addr().unwrap();

        let proto = ServerMode::OrderedReliable(NativeOrderedReliableConfig::new());
        match NativeIO::bind(proto, taken).await {
            Ok(_) => panic!("bind unexpectedly succeeded on an occupied port {taken}"),
            Err(e) => {
                assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::AddrInUse,
                    "kind was flattened; got {:?} ({e})",
                    e.kind()
                );
                assert!(
                    e.raw_os_error().is_some(),
                    "errno was stringified away; got {e:?}"
                );
            }
        }
    }

    #[fixture]
    #[once]
    fn protocols() -> Vec<ServerMode<NativeIO>> {
        /*use std::io::Read;
          use itertools::Itertools;
        // NOTE: This is a dev-only pkcs12 bundle that is periodically renewed. It is not used
        // to actually protect any sensitive data
        let pkcs_12_der = ureq::get("https://thomaspbraun.com/dev_certificate.p12")
            .call()
            .unwrap()
            .into_reader()
            .bytes()
            .try_collect::<u8, Vec<u8>, _>()
            .unwrap();*/

        vec![
            ServerMode::OrderedReliable(NativeOrderedReliableConfig::new()),
            ServerMode::OrderedReliableSecure(NativeSecureConfig::self_signed().unwrap()),
            ServerMode::P2P(NativeP2PConfig::self_signed()),
            /*ServerMode::<NativeIO>::load_secure_from_bytes(
                &pkcs_12_der,
                "password",
                "thomaspbraun.com",
            )
            .unwrap(),
            ServerMode::<NativeIO>::load_p2p_from_bytes(
                &pkcs_12_der,
                "password",
                "thomaspbraun.com",
            )
            .unwrap(),*/
        ]
    }

    #[fixture]
    #[once]
    fn client_config() -> NativeClientConfig {
        let certs = citadel_wire::tls::load_native_certs().unwrap();
        NativeClientConfig::new(Arc::new(
            citadel_wire::tls::cert_vec_to_secure_client_config(&certs).unwrap(),
        ))
    }

    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[timeout(Duration::from_secs(60))]
    #[cfg_attr(
        feature = "multi-threaded",
        citadel_io::tokio::test(flavor = "multi_thread")
    )]
    #[cfg_attr(
        not(feature = "multi-threaded"),
        citadel_io::tokio::test(flavor = "current_thread")
    )]
    async fn test_tcp_or_tls(
        #[case] addr: SocketAddr,
        protocols: &Vec<ServerMode<NativeIO>>,
        client_config: &NativeClientConfig,
    ) -> std::io::Result<()> {
        citadel_logging::setup_log();

        if let Some(reason) = unsupported_here(addr) {
            log::warn!(target: "citadel", "Skipping {addr}: {reason}");
            return Ok(());
        }

        for proto in protocols {
            log::trace!(target: "citadel", "Testing proto {:?} @ {:?}", proto, addr);

            let res = bind_retrying_reserved_ports(proto.clone(), addr).await;

            if let Err(err) = res.as_ref() {
                log::error!(target: "citadel", "Error creating primary socket: {err:?}");
            }

            let (mut listener, addr) = res.unwrap();
            log::trace!(target: "citadel", "Bind/connect addr: {addr:?}");

            let server = async move {
                let next = listener.next().await;
                log::trace!(target: "citadel", "[Server] Next conn: {next:?}");
                let (stream, peer_addr) = next.unwrap().unwrap();
                on_server_received_connection(stream, peer_addr).await
            };

            let client = async move {
                let stream = NativeIO::connect(client_config, addr).await.unwrap();
                on_client_received_stream(stream).await
            };

            let res = citadel_io::tokio::try_join!(server, client);
            log::trace!("RES: {res:?}");
            if let Err(err) = res {
                log::error!(target: "citadel", "Error: {err:?}");
            }
            log::trace!(target: "citadel", "Ended");
        }

        Ok(())
    }

    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[timeout(Duration::from_secs(60))]
    #[cfg_attr(
        feature = "multi-threaded",
        citadel_io::tokio::test(flavor = "multi_thread")
    )]
    #[cfg_attr(
        not(feature = "multi-threaded"),
        citadel_io::tokio::test(flavor = "current_thread")
    )]
    async fn test_many_proto_conns(
        #[case] addr: SocketAddr,
        protocols: &Vec<ServerMode<NativeIO>>,
        client_config: &NativeClientConfig,
    ) -> std::io::Result<()> {
        citadel_logging::setup_log();

        if let Some(reason) = unsupported_here(addr) {
            log::warn!(target: "citadel", "Skipping {addr}: {reason}");
            return Ok(());
        }

        let count = 32; // keep this value low to ensure that runners don't get exhausted and run out of FD's
        for proto in protocols {
            log::trace!(target: "citadel", "Testing proto {:?}", proto);
            let cnt = &AtomicUsize::new(0);

            let res = bind_retrying_reserved_ports(proto.clone(), addr).await;

            if let Err(err) = res.as_ref() {
                log::error!(target: "citadel", "Error creating primary socket w/mode {proto:?}: {err:?}");
            }

            let (mut listener, addr) = res.unwrap();
            log::trace!(target: "citadel", "Bind/connect addr: {addr:?}");

            let server = async move {
                let stream = async_stream::stream! {
                    while let Some(stream) = listener.next().await {
                        yield stream.unwrap()
                    }
                };

                stream
                    .map(Ok)
                    .try_for_each_concurrent(None, |(stream, peer_addr)| async move {
                        on_server_received_connection(stream, peer_addr).await
                    })
                    .await
            };

            let client = FuturesUnordered::new();

            for _ in 0..count {
                client.push(async move {
                    let stream = NativeIO::connect(client_config, addr).await?;
                    on_client_received_stream(stream).await?;
                    let _ = cnt.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                });
            }

            let client = client.try_collect::<Vec<()>>();
            // if server ends, bad. If client ends, maybe good
            let res = citadel_io::tokio::select! {
                res0 = server => {
                    log::error!(target: "citadel", "Server ended! {res0:?}");
                    res0
                },
                res1 = client => {
                    res1.map(|_| ())
                }
            };

            log::trace!(target: "citadel", "Res: {res:?}");

            assert_eq!(cnt.load(Ordering::SeqCst), count);

            log::trace!(target: "citadel", "Ended proto test for singular proto successfully");
        }

        Ok(())
    }

    async fn on_server_received_connection(
        stream: GenericNetworkStream,
        peer_addr: SocketAddr,
    ) -> std::io::Result<()> {
        log::trace!(target: "citadel", "[Server] Received stream from {peer_addr}");
        let (mut sink, mut stream) = safe_split_stream(stream);
        let packet = stream.next().await.unwrap()?;
        log::trace!(target: "citadel", "[Server] Received packet");
        assert_eq!(&packet[..], &[100u8]);
        sink.write_raw_frame(BytesMut::from(&[100u8] as &[u8]).freeze())
            .await?;
        sink.flush().await?;
        log::trace!(target: "citadel", "[Server] Sent packet");
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    async fn on_client_received_stream(stream: GenericNetworkStream) -> std::io::Result<()> {
        let (mut sink, mut stream) = safe_split_stream(stream);
        log::trace!(target: "citadel", "Client connected");
        sink.write_raw_frame(BytesMut::from(&[100u8] as &[u8]).freeze())
            .await?;
        sink.flush().await?;
        log::trace!(target: "citadel", "Client - sent packet");
        let packet_opt = stream.next().await;
        log::trace!(target: "citadel", "Client - next: {packet_opt:?}");
        let packet = packet_opt.unwrap()?;
        log::trace!(target: "citadel", "Client - obtained packet");
        assert_eq!(&packet[..], &[100u8]);
        Ok(())
    }
}
