//! A node on the numbered-attempt hole-punch protocol (0.11) meeting a peer on
//! the unpaired one (before 0.11) must give up on the punch at once, so its
//! caller falls back: C2S preconnect to TCP, a P2P channel to its relay. It
//! must not run attempts the peer cannot pair, each until its timer fires.
//!
//! The scripted peer does what the unpaired driver did on its first attempt:
//! open a subscription, send its NAT type, and wait for the peer's. The
//! per-attempt timeout is an hour, so a fall-back that waited on any attempt
//! timer would trip the hang guard instead. Outcomes only, no latency.

use citadel_io::tokio;
use citadel_wire::nat_identification::NatType;
use citadel_wire::udp_traversal::udp_hole_puncher::UdpHolePuncher;
use netbeam::reliable_conn::ReliableOrderedStreamToTargetExt;
use netbeam::sync::subscription::Subscribable;
use netbeam::sync::test_utils::create_streams_with_addrs;
use std::time::Duration;

const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3600);
/// Guards against a hang only.
const HANG_GUARD: Duration = Duration::from_secs(60);

#[tokio::test]
async fn a_peer_on_the_unpaired_protocol_is_refused_without_waiting_on_a_timer() {
    let (local, remote) = create_streams_with_addrs().await;

    let unpaired_peer = async {
        let stream = remote.initiate_subscription().await.unwrap();
        stream.send_serialized(NatType::default()).await.unwrap();
        // The unpaired driver now waits for the peer's NAT type, and holds
        // its subscription while it does.
        let _ = stream.recv_serialized::<NatType>().await;
        std::future::pending::<()>().await
    };

    let punch = UdpHolePuncher::new_timeout(&local, Default::default(), ATTEMPT_TIMEOUT);
    let result = tokio::select! {
        result = tokio::time::timeout(HANG_GUARD, punch) => {
            result.expect("the punch kept waiting on a peer that cannot pair its attempts")
        }
        _ = unpaired_peer => unreachable!("the scripted peer never finishes"),
    };
    let err = result.expect_err("a punch against an unpaired-protocol peer succeeded");
    assert!(
        err.to_string().contains("does not number its attempts"),
        "the punch failed, but not by recognising the older protocol: {err:#}"
    );
}
