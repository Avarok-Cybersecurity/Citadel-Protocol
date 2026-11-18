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

    let config = NativeClientConfig::new(Arc::new(
        citadel_wire::quic::insecure::rustls_client_config(),
    ));
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
