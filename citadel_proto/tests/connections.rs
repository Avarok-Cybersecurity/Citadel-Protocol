#[cfg(test)]
pub mod tests {
    use bytes::BytesMut;
    use citadel_io::tokio;
    use citadel_proto::prelude::*;
    use citadel_wire::exports::tokio_rustls::rustls::ClientConfig;
    use citadel_wire::socket_helpers::is_ipv6_enabled;
    use futures::stream::FuturesUnordered;
    use futures::TryStreamExt;
    use futures::{SinkExt, StreamExt};
    use rstest::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[fixture]
    #[once]
    fn protocols() -> Vec<ServerUnderlyingProtocol> {
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
            ServerUnderlyingProtocol::tcp(),
            ServerUnderlyingProtocol::new_tls_self_signed().unwrap(),
            ServerUnderlyingProtocol::new_quic_self_signed(),
            /*ServerUnderlyingProtocol::load_tls_from_bytes(
                &pkcs_12_der,
                "password",
                "thomaspbraun.com",
            )
            .unwrap(),
            ServerUnderlyingProtocol::load_quic_from_bytes(
                &pkcs_12_der,
                "password",
                "thomaspbraun.com",
            )
            .unwrap(),*/
        ]
    }

    #[fixture]
    #[once]
    fn client_config() -> Arc<ClientConfig> {
        let certs = citadel_wire::tls::load_native_certs().unwrap();
        Arc::new(citadel_wire::tls::cert_vec_to_secure_client_config(&certs).unwrap())
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
        protocols: &Vec<ServerUnderlyingProtocol>,
        client_config: &Arc<ClientConfig>,
    ) -> std::io::Result<()> {
        citadel_logging::setup_log();

        if !is_ipv6_enabled() && addr.is_ipv6() {
            log::trace!(target: "citadel", "Skipping ipv6 test since ipv6 is not enabled locally");
            return Ok(());
        }

        if !cfg!(feature = "multi-threaded") {
            log::warn!(target: "citadel", "Skipping test since only works on multi-threaded mode");
            return Ok(());
        }

        for proto in protocols {
            log::trace!(target: "citadel", "Testing proto {:?} @ {:?}", &proto, addr);

            let res = CitadelNode::<StackedRatchet>::server_create_primary_listen_socket(
                proto.clone(),
                addr,
            );

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
                let (stream, _) =
                    CitadelNode::<StackedRatchet>::c2s_connect_defaults(None, addr, client_config)
                        .await
                        .unwrap();
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
        protocols: &Vec<ServerUnderlyingProtocol>,
        client_config: &Arc<ClientConfig>,
    ) -> std::io::Result<()> {
        citadel_logging::setup_log();

        if !cfg!(feature = "multi-threaded") {
            log::trace!(target: "citadel", "Skipping test since only works on multi-threaded mode");
            return Ok(());
        }

        if !is_ipv6_enabled() && addr.is_ipv6() {
            log::warn!(target: "citadel", "Skipping ipv6 test since ipv6 is not enabled locally");
            return Ok(());
        }

        let count = 32; // keep this value low to ensure that runners don't get exhausted and run out of FD's
        for proto in protocols {
            log::trace!(target: "citadel", "Testing proto {:?}", &proto);
            let cnt = &AtomicUsize::new(0);

            let res = CitadelNode::<StackedRatchet>::server_create_primary_listen_socket(
                proto.clone(),
                addr,
            );

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
                    let (stream, _) = CitadelNode::<StackedRatchet>::c2s_connect_defaults(
                        None,
                        addr,
                        client_config,
                    )
                    .await?;
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
        sink.send(BytesMut::from(&[100u8] as &[u8]).freeze())
            .await?;
        log::trace!(target: "citadel", "[Server] Sent packet");
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    async fn on_client_received_stream(stream: GenericNetworkStream) -> std::io::Result<()> {
        let (mut sink, mut stream) = safe_split_stream(stream);
        log::trace!(target: "citadel", "Client connected");
        sink.send(BytesMut::from(&[100u8] as &[u8]).freeze())
            .await?;
        log::trace!(target: "citadel", "Client - sent packet");
        let packet_opt = stream.next().await;
        log::trace!(target: "citadel", "Client - next: {packet_opt:?}");
        let packet = packet_opt.unwrap()?;
        log::trace!(target: "citadel", "Client - obtained packet");
        assert_eq!(&packet[..], &[100u8]);
        Ok(())
    }
}
