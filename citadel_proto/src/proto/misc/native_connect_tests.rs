//! A client connect ends at its deadline at every stage, including the TLS handshake.

use super::*;
use crate::proto::misc::native_io::NativeClientConfig;
use citadel_io::tokio;
use citadel_user::serialization::SyncIO;

#[tokio::test]
async fn a_server_that_stalls_the_tls_handshake_fails_the_connect_at_its_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Offers TLS, then never answers the client's hello; the socket stays open.
    let stalling_server = tokio::spawn(async move {
        let (stream, external_addr) = listener.accept().await.unwrap();
        let offer = FirstPacket::OrderedReliableSecure {
            domain: None,
            external_addr,
            is_self_signed: true,
        }
        .serialize_to_vector()
        .unwrap();
        let stream = super::super::write_one_packet(stream, offer).await.unwrap();
        std::future::pending::<()>().await;
        drop(stream);
    });

    let config = NativeClientConfig::new(
        Arc::new(citadel_wire::quic::insecure::rustls_client_config()),
        false,
    );
    let deadline = Duration::from_millis(500);
    // An upper bound only, far above `deadline`: without one this test would wait for ever.
    let outcome = tokio::time::timeout(
        Duration::from_secs(20),
        c2s_connect(Some(deadline), addr, &config),
    )
    .await
    .expect("the connect outlived its deadline: the TLS handshake is unbounded");
    let Err(err) = outcome else {
        panic!("a stalled handshake cannot succeed");
    };
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err:?}");
    stalling_server.abort();
}

/// A server that offers `first_packet` and holds the socket open.
async fn offering(first_packet: FirstPacket) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let offer = first_packet.serialize_to_vector().unwrap();
        let stream = super::super::write_one_packet(stream, offer).await.unwrap();
        std::future::pending::<()>().await;
        drop(stream);
    });
    (addr, server)
}

fn client_config(require_cert_verification: bool) -> NativeClientConfig {
    NativeClientConfig {
        config: Arc::new(citadel_wire::quic::insecure::rustls_client_config()),
        require_cert_verification,
    }
}

#[tokio::test]
async fn a_client_that_requires_verification_refuses_a_plaintext_offer() {
    let external_addr = "127.0.0.1:1".parse().unwrap();
    let (addr, server) = offering(FirstPacket::OrderedReliable { external_addr }).await;
    let outcome = c2s_connect(Some(Duration::from_secs(5)), addr, &client_config(true)).await;
    server.abort();
    assert!(
        outcome.is_err(),
        "a client that requires certificate verification connected over plain TCP"
    );
}

#[tokio::test]
async fn a_client_that_does_not_require_verification_takes_a_plaintext_offer() {
    let external_addr = "127.0.0.1:1".parse().unwrap();
    let (addr, server) = offering(FirstPacket::OrderedReliable { external_addr }).await;
    let outcome = c2s_connect(Some(Duration::from_secs(5)), addr, &client_config(false)).await;
    server.abort();
    assert!(matches!(
        outcome,
        Ok(GenericNetworkStream::OrderedReliable(_))
    ));
}

/// A server that says it is self-signed, then completes TLS with a self-signed certificate.
async fn self_signed_tls() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = citadel_wire::tls::create_server_self_signed_config()
        .unwrap()
        .tls_acceptor;
    let server = tokio::spawn(async move {
        let (stream, external_addr) = listener.accept().await.unwrap();
        let offer = FirstPacket::OrderedReliableSecure {
            domain: None,
            external_addr,
            is_self_signed: true,
        }
        .serialize_to_vector()
        .unwrap();
        let stream = super::super::write_one_packet(stream, offer).await.unwrap();
        let _tls = acceptor.accept(stream).await;
        std::future::pending::<()>().await;
    });
    (addr, server)
}

/// A client whose certificate verifier trusts one unrelated self-signed certificate only.
fn verifying_client(require_cert_verification: bool) -> NativeClientConfig {
    let unrelated = citadel_wire::tls::create_server_self_signed_config()
        .unwrap()
        .quic_chain;
    NativeClientConfig {
        config: Arc::new(citadel_wire::tls::create_rustls_client_config(&unrelated).unwrap()),
        require_cert_verification,
    }
}

#[tokio::test]
async fn a_self_signed_offer_does_not_switch_verification_off_when_it_is_required() {
    let (addr, server) = self_signed_tls().await;
    let outcome = c2s_connect(Some(Duration::from_secs(5)), addr, &verifying_client(true)).await;
    server.abort();
    assert!(
        outcome.is_err(),
        "an unverifiable certificate was accepted because the server said it was self-signed"
    );
}

#[tokio::test]
async fn a_self_signed_offer_is_taken_when_verification_is_not_required() {
    let (addr, server) = self_signed_tls().await;
    let outcome = c2s_connect(Some(Duration::from_secs(5)), addr, &verifying_client(false)).await;
    server.abort();
    assert!(outcome.is_ok(), "{:?}", outcome.err());
}
