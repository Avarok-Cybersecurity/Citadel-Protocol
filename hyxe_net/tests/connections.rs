#[cfg(test)]
pub mod tests {
    use std::sync::Arc;
    use futures::StreamExt;
    use std::time::Duration;
    use std::net::SocketAddr;
    use hyxe_net::prelude::*;
    use rstest::*;
    use futures::stream::FuturesUnordered;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use rand::{SeedableRng, Rng};
    use hyxe_wire::exports::tokio_rustls::rustls::ClientConfig;
    use hyxe_wire::socket_helpers::is_ipv6_enabled;
    use itertools::Itertools;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn setup_log() {
        std::env::set_var("RUST_LOG", "lusna=trace");
        //std::env::set_var("RUST_LOG", "error");
        let _ = env_logger::try_init();
        log::trace!(target: "lusna", "TRACE enabled");
        log::trace!(target: "lusna", "INFO enabled");
        log::warn!(target: "lusna", "WARN enabled");
        log::error!(target: "lusna", "ERROR enabled");
    }

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
    #[tokio::test]
    async fn test_tcp_or_tls(#[case] addr: SocketAddr,
                             protocols: &Vec<UnderlyingProtocol>,
                             client_config: &Arc<ClientConfig>) -> std::io::Result<()> {
        setup_log();

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
                let (mut stream, peer_addr) = next.unwrap().unwrap();
                log::trace!(target: "lusna", "[Server] Received stream from {}", peer_addr);
                let buf = &mut [0u8;64];
                let res = stream.read(buf).await;
                log::trace!(target: "lusna", "Server-res: {:?}", res);
                assert_eq!(buf[0], 0xfb, "Invalid read");
                let _ = stream.write(&[0xfa]).await.unwrap();
                stream.shutdown().await.unwrap();
            };

            let client = async move {
                let (mut stream, _) = HdpServer::c2s_connect_defaults(None, addr, client_config).await.unwrap();
                log::trace!(target: "lusna", "Client connected");
                let res = stream.write(&[0xfb]).await;
                log::trace!(target: "lusna", "Client connected - A02 {:?}", res);
                let buf = &mut [0u8;64];
                let res = stream.read(buf).await;
                log::trace!(target: "lusna", "Client connected - AO3 {:?}", res);
                assert_eq!(buf[0], 0xfa, "Invalid read - client");
            };

            let _ = tokio::join!(server, client);
            log::trace!(target: "lusna", "Ended");
        }

        Ok(())
    }

    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[tokio::test]
    async fn test_many_proto_conns(#[case] addr: SocketAddr,
                                   protocols: &Vec<UnderlyingProtocol>,
                                   client_config: &Arc<ClientConfig>) -> std::io::Result<()> {
        setup_log();

        if !is_ipv6_enabled() && addr.is_ipv6() {
            log::trace!(target: "lusna", "Skipping ipv6 test since ipv6 is not enabled locally");
            return Ok(())
        }

        let count = 32; // keep this value low to ensure that runners don't get exhausted and run out of FD's
        for proto in protocols {
            // give sleep to give time for conns to drop
            tokio::time::sleep(Duration::from_millis(100)).await;
            log::trace!(target: "lusna", "Testing proto {:?}", &proto);
            let cnt = &AtomicUsize::new(0);

            let (mut listener, addr) = HdpServer::server_create_primary_listen_socket(proto.clone(),addr).unwrap();
            log::trace!(target: "lusna", "Bind/connect addr: {:?}", addr);

            let server = async move {
                loop {
                    let next = listener.next().await;
                    log::trace!(target: "lusna", "[Server] Next conn: {:?}", next);
                    let (mut stream, peer_addr) = next.unwrap().unwrap();
                    tokio::spawn(async move {
                        log::trace!(target: "lusna", "[Server] Received stream from {}", peer_addr);
                        let buf = &mut [0u8;64];
                        let res = stream.read(buf).await;
                        log::trace!(target: "lusna", "Server-res: {:?}", res);
                        assert_eq!(buf[0], 0xfb, "Invalid read");
                        let _ = stream.write(&[0xfa]).await.unwrap();
                        stream.shutdown().await.unwrap();
                    });
                }
            };

            let client = FuturesUnordered::new();

            for _ in 0..count {
                client.push(async move {
                    let mut rng = rand::rngs::StdRng::from_entropy();
                    tokio::time::sleep(Duration::from_millis(rng.gen_range(10, 50))).await;
                    let (mut stream, _) = HdpServer::c2s_connect_defaults(None, addr, client_config).await.unwrap();
                    log::trace!(target: "lusna", "Client connected");
                    let res = stream.write(&[0xfb]).await;
                    log::trace!(target: "lusna", "Client connected - A02 {:?}", res);
                    let buf = &mut [0u8;64];
                    let res = stream.read(buf).await;
                    log::trace!(target: "lusna", "Client connected - AO3 {:?}", res);
                    assert_eq!(buf[0], 0xfa, "Invalid read - client");
                    let _ = cnt.fetch_add(1, Ordering::SeqCst);
                });
            }

            let client = client.collect::<Vec<()>>();
            // if server ends, bad. If client ends, maybe good
            let res = tokio::select! {
                res0 = server => {
                    res0
                },
                res1 = client => {
                    res1
                }
            };

            log::trace!(target: "lusna", "Res: {:?}", res);

            assert_eq!(cnt.load(Ordering::SeqCst), count);

            log::trace!(target: "lusna", "Ended proto test for singular proto successfully");
        }

        Ok(())
    }
}