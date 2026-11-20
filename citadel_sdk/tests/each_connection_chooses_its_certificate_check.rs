#![cfg(not(target_family = "wasm"))]
//! One node makes two connections to the same server; each states what it demands of the
//! server's certificate. One that requires a verified certificate is refused by a server whose
//! certificate the node's roots do not verify, or that offers no TLS at all; one that accepts a
//! self-signed server connects to it.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::{Events, GroupTestKernel};
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_test_node;
    use std::net::SocketAddr;
    use uuid::Uuid;

    /// A test server (plain TCP), or one offering `mode` instead, run until the test ends.
    fn server(
        mode: Option<ServerMode<NativeIO>>,
    ) -> (impl std::future::Future<Output = ()>, SocketAddr) {
        let (node, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |b| {
            if let Some(mode) = mode {
                let _ = b.with_underlying_protocol(mode);
            }
        });
        (async move { node.await.map(|_| ()).unwrap() }, addr)
    }

    /// Returns once `addr` accepts connections: a server offering TLS binds as it starts.
    async fn listening(addr: SocketAddr) {
        let probe = async {
            while tokio::net::TcpStream::connect(addr).await.is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), probe)
            .await
            .expect("the server did not start listening");
    }

    /// A node that trusts one unrelated certificate only, so no server here verifies under its
    /// roots.
    fn trusting_an_unrelated_certificate(builder: &mut DefaultNodeBuilder) {
        let unrelated = citadel_wire::tls::create_server_self_signed_config()
            .unwrap()
            .quic_chain;
        let _ = builder.with_custom_certs(&unrelated).unwrap();
    }

    /// A node built to take any certificate unverified.
    fn accepting_any_certificate(builder: &mut DefaultNodeBuilder) {
        let _ = builder.with_insecure_skip_cert_verification();
    }

    /// The outcome of a strict connection, then a permissive one, from one node to `addr`, the
    /// node's client TLS set by `trust`.
    async fn strict_then_permissive(
        server: impl std::future::Future<Output = ()>,
        addr: SocketAddr,
        trust: fn(&mut DefaultNodeBuilder),
    ) -> (Result<(), String>, Result<(), String>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let body = move |remote: NodeRemote<StackedRatchet>, _: Events| async move {
            let connect = |verification| {
                let remote = remote.clone();
                async move {
                    remote
                        .connect_with_defaults(
                            AuthenticationRequest::transient(Uuid::new_v4(), addr),
                            verification,
                        )
                        .await
                        .map(drop)
                        .map_err(|err| err.into_string())
                }
            };
            let strict = connect(CertVerification::Required).await;
            let permissive = connect(CertVerification::SelfSignedAccepted).await;
            let _ = tx.send((strict, permissive));
            remote.shutdown().await
        };
        let mut builder = DefaultNodeBuilder::default();
        let _ = builder
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level());
        trust(&mut builder);
        let client = builder.build(GroupTestKernel::new(body)).unwrap();
        tokio::select! {
            _ = server => panic!("the server ended first"),
            res = async { listening(addr).await; client.await } => { res.unwrap(); }
        }
        rx.await.expect("the client reported nothing")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn against_a_self_signed_server_only_the_connection_that_accepts_it_connects() {
        citadel_logging::setup_log();
        let (server, addr) = server(Some(ServerMode::OrderedReliableSecure(
            NativeSecureConfig::self_signed().unwrap(),
        )));
        let (strict, permissive) =
            strict_then_permissive(server, addr, trusting_an_unrelated_certificate).await;
        let refused = strict.expect_err("a strict connection took an unverifiable certificate");
        assert!(refused.contains("certificate"), "{refused}");
        permissive.expect("a permissive connection refused a self-signed server");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn against_a_server_without_tls_only_the_permissive_connection_connects() {
        citadel_logging::setup_log();
        let (server, addr) = server(None);
        let (strict, permissive) =
            strict_then_permissive(server, addr, trusting_an_unrelated_certificate).await;
        let refused = strict.expect_err("a strict connection took plain TCP");
        assert!(refused.contains("offered none"), "{refused}");
        permissive.expect("a permissive connection refused plain TCP");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_that_accepts_any_certificate_refuses_a_strict_connection() {
        citadel_logging::setup_log();
        let (server, addr) = server(Some(ServerMode::OrderedReliableSecure(
            NativeSecureConfig::self_signed().unwrap(),
        )));
        let (strict, permissive) =
            strict_then_permissive(server, addr, accepting_any_certificate).await;
        let refused =
            strict.expect_err("a strict connection was verified by a verifier that accepts any");
        assert!(refused.contains("accept any certificate"), "{refused}");
        permissive.expect("a permissive connection refused a self-signed server");
    }
}
