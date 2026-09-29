//! `drive` end to end, for outcomes that need no race to reach.

use super::DualStackUdpHolePuncher;
use crate::nat_identification::NatType;
use crate::socket_helpers::get_udp_socket;
use crate::udp_traversal::hole_punch_config::HolePunchConfig;
use citadel_io::tokio;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::subscription::Subscribable;
use netbeam::sync::test_utils::create_streams_with_addrs;
use std::time::Duration;

/// Method3 gives up after 3 s. Well inside one attempt's 20 s budget.
const PROMPT: Duration = Duration::from_secs(10);

fn aimed_at_silence(
    app: NetworkEndpoint,
    silent_peer: &std::net::UdpSocket,
) -> DualStackUdpHolePuncher {
    let config = HolePunchConfig::new(
        &NatType::default(),
        &[silent_peer.local_addr().unwrap()],
        &[],
        vec![get_udp_socket("127.0.0.1:0").unwrap()],
    );
    DualStackUdpHolePuncher::new(app.node_type(), Default::default(), config, app).unwrap()
}

/// When every puncher on both sides has failed, no winner can appear. Both
/// sides used to know that and still wait for the attempt's timeout, so the
/// retry started 20 s late.
#[tokio::test]
async fn a_mutual_failure_ends_the_attempt_promptly() {
    let (a, b) = create_streams_with_addrs().await;
    let silent_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let silent_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

    let (res_a, res_b) = tokio::time::timeout(PROMPT, async {
        tokio::join!(
            aimed_at_silence(a, &silent_a),
            aimed_at_silence(b, &silent_b)
        )
    })
    .await
    .expect("both sides had failed, but the attempt waited for its timeout");

    assert!(res_a.is_err() && res_b.is_err());
}
