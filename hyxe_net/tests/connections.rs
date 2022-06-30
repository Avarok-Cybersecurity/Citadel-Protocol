#[cfg(test)]
pub mod tests {
    use std::sync::Arc;
    use futures::{StreamExt, SinkExt};
    use std::time::Duration;
    use std::net::SocketAddr;
    use hyxe_net::prelude::*;
    use rstest::*;
    use futures::stream::FuturesUnordered;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use hyxe_wire::exports::tokio_rustls::rustls::ClientConfig;
    use hyxe_wire::socket_helpers::is_ipv6_enabled;
    use itertools::Itertools;
    use futures::TryStreamExt;
    use bytes::BytesMut;

    #[fixture]
    #[once]
    fn protocols() -> Vec<UnderlyingProtocol> {
        use std::io::Read;
        // NOTE: This is a dev-only pkcs12 bundle that is periodically renewed. It is not used
        // to actually protect any sensitive data
        let pkcs_12_der = ureq::get("https://thomaspbraun.com/dev_certificate.p12").call().unwrap().into_reader().bytes().try_collect::<u8, Vec<u8>, _>().unwrap();

        vec![
            UnderlyingProtocol::Tcp,
            UnderlyingProtocol::new_tls_self_signed().unwrap(),
            UnderlyingProtocol::new_quic_self_signed(),
            UnderlyingProtocol::load_tls_from_bytes(&pkcs_12_der, "password", "thomaspbraun.com").unwrap(),
            UnderlyingProtocol::load_quic_from_bytes(&pkcs_12_der, "password", "thomaspbraun.com").unwrap()
        ]
    }

    #[fixture]
    #[once]
    fn client_config() -> Arc<ClientConfig> {
        let certs = hyxe_wire::tls::load_native_certs().unwrap();
        Arc::new(hyxe_wire::tls::cert_vec_to_secure_client_config(&certs).unwrap())
    }

    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[timeout(Duration::from_secs(240))]
    #[tokio::test(flavor="multi_thread")]
    async fn test_tcp_or_tls(#[case] addr: SocketAddr,
                             protocols: &Vec<UnderlyingProtocol>,
                             client_config: &Arc<ClientConfig>) -> std::io::Result<()> {
        lusna_logging::setup_log();

        if !is_ipv6_enabled() && addr.is_ipv6() {
            log::trace!(target: "lusna", "Skipping ipv6 test since ipv6 is not enabled locally");
            return Ok(())
        }

        for proto in protocols {
            log::trace!(target: "lusna", "Testing proto {:?}", &proto);

            let (mut listener, addr) = HdpServer::server_create_primary_listen_socket(proto.clone(),addr).unwrap();
            log::trace!(target: "lusna", "Bind/connect addr: {:?}", addr);

            let server = async move {
                let next = listener.next().await;
                log::trace!(target: "lusna", "[Server] Next conn: {:?}", next);
                let (stream, peer_addr) = next.unwrap().unwrap();
                on_server_received_connection(stream, peer_addr).await
            };

            let client = async move {
                let (stream, _) = HdpServer::c2s_connect_defaults(None, addr, client_config).await.unwrap();
                on_client_received_stream(stream).await
            };

            let _ = tokio::join!(server, client);
            log::trace!(target: "lusna", "Ended");
        }

        Ok(())
    }

    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[timeout(Duration::from_secs(240))]
    #[tokio::test(flavor="multi_thread")]
    async fn test_many_proto_conns(#[case] addr: SocketAddr,
                                   protocols: &Vec<UnderlyingProtocol>,
                                   client_config: &Arc<ClientConfig>) -> std::io::Result<()> {
        lusna_logging::setup_log();

        if !is_ipv6_enabled() && addr.is_ipv6() {
            log::trace!(target: "lusna", "Skipping ipv6 test since ipv6 is not enabled locally");
            return Ok(())
        }

        let count = 32; // keep this value low to ensure that runners don't get exhausted and run out of FD's
        for proto in protocols {
            log::trace!(target: "lusna", "Testing proto {:?}", &proto);
            let cnt = &AtomicUsize::new(0);

            let (mut listener, addr) = HdpServer::server_create_primary_listen_socket(proto.clone(),addr).unwrap();
            log::trace!(target: "lusna", "Bind/connect addr: {:?}", addr);

            let server = async move {
                let stream = async_stream::stream! {
                    while let Some(stream) = listener.next().await {
                        yield stream.unwrap()
                    }
                };

                stream.map(Ok).try_for_each_concurrent(None, |(stream, peer_addr)| async move {
                    on_server_received_connection(stream, peer_addr).await
                }).await
            };

            let client = FuturesUnordered::new();

            for _ in 0..count {
                client.push(async move {
                    let (stream, _) = HdpServer::c2s_connect_defaults(None, addr, client_config).await?;
                    on_client_received_stream(stream).await?;
                    let _ = cnt.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                });
            }

            let client = client.try_collect::<Vec<()>>();
            // if server ends, bad. If client ends, maybe good
            let res = tokio::select! {
                res0 = server => {
                    res0
                },
                res1 = client => {
                    res1.map(|_| ())
                }
            };

            log::trace!(target: "lusna", "Res: {:?}", res);

            assert_eq!(cnt.load(Ordering::SeqCst), count);

            log::trace!(target: "lusna", "Ended proto test for singular proto successfully");
        }

        Ok(())
    }

    async fn on_server_received_connection(stream: GenericNetworkStream, peer_addr: SocketAddr) -> std::io::Result<()> {
        log::trace!(target: "lusna", "[Server] Received stream from {}", peer_addr);
        let (mut sink, mut stream) = safe_split_stream(stream);
        let packet = stream.next().await.unwrap()?;
        assert_eq!(&packet[..], &[100u8]);
        sink.send(BytesMut::from(&[100u8] as &[u8]).freeze()).await?;
        Ok(())
    }

    async fn on_client_received_stream(stream: GenericNetworkStream) -> std::io::Result<()> {
        let (mut sink, mut stream) = safe_split_stream(stream);
        log::trace!(target: "lusna", "Client connected");
        sink.send(BytesMut::from(&[100u8] as &[u8]).freeze()).await?;
        let packet = stream.next().await.unwrap()?;
        assert_eq!(&packet[..], &[100u8]);
        Ok(())
    }
}