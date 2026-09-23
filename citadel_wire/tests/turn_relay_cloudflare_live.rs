//! Manual live smoke against Cloudflare Realtime TURN (turn.cloudflare.com), over UDP 3478 and
//! TLS 443. Never run by CI: it needs a freshly minted short-TTL credential in the environment.
//!
//! ```text
//! # mint (TTL 300 s) with the key's API token, then:
//! CF_TURN_USERNAME=... CF_TURN_CREDENTIAL=... \
//!   cargo nextest run -p citadel_wire --test turn_relay_cloudflare_live --run-ignored all
//! ```
//!
//! The peer is a plain UDP socket on this host, so its datagrams reach the relay from this host's
//! public address — the permission installed is the allocation's own server-reflexive IP.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use citadel_io::tokio;
use citadel_io::tokio::net::UdpSocket;
use citadel_wire::udp_traversal::turn_relay::{TurnAllocation, TurnServerCredential};
use rstest::rstest;

const STEP: Duration = Duration::from_secs(10);

fn credential(url: &str) -> TurnServerCredential {
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set"));
    TurnServerCredential::new(
        url,
        var("CF_TURN_USERNAME"),
        var("CF_TURN_CREDENTIAL"),
        Some(SystemTime::now() + Duration::from_secs(300)),
    )
    .unwrap()
}

#[rstest]
#[case("turn:turn.cloudflare.com:3478?transport=udp")]
#[case("turns:turn.cloudflare.com:443?transport=tcp")]
#[ignore = "live: needs CF_TURN_USERNAME / CF_TURN_CREDENTIAL minted from a Cloudflare TURN key"]
#[tokio::test]
async fn cloudflare_relays_both_ways(#[case] url: &str) {
    citadel_logging::setup_log();
    let native = citadel_wire::tls::load_native_certs_async().await.unwrap();
    let roots = Arc::new(citadel_wire::tls::cert_vec_to_secure_client_config(&native).unwrap());
    let alloc = TurnAllocation::allocate(&credential(url), Some(roots))
        .await
        .unwrap_or_else(|e| panic!("allocate via {url}: {e}"));
    log::info!(target: "citadel", "relayed {} mapped {}", alloc.relayed_addr(), alloc.mapped_addr());

    let peer = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    alloc
        .create_permissions(&[alloc.mapped_addr().ip()])
        .await
        .unwrap();
    // The peer's NAT port toward the relay is unknown until its first datagram arrives.
    let (peer_public, first) = tokio::time::timeout(STEP, async {
        loop {
            peer.send_to(b"hello-relay", alloc.relayed_addr())
                .await
                .unwrap();
            if let Ok(got) =
                tokio::time::timeout(Duration::from_millis(500), alloc.recv_from()).await
            {
                return got.unwrap();
            }
        }
    })
    .await
    .expect("no datagram relayed from the peer");
    assert_eq!(first, b"hello-relay");

    alloc.bind_channel(peer_public).await.unwrap();
    let media = vec![0x5Au8; 1024];
    alloc.send_to(peer_public, &media).unwrap();
    let mut buf = [0u8; 2048];
    let (n, from) = tokio::time::timeout(STEP, peer.recv_from(&mut buf))
        .await
        .expect("relay did not deliver to the peer")
        .unwrap();
    assert_eq!((from, &buf[..n]), (alloc.relayed_addr(), &media[..]));
}
