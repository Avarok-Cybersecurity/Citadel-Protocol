use super::*;
use citadel_io::tokio;
use embedded_semver::Semver;
use netbeam::sync::test_utils::create_streams_with_addrs;
use std::time::Duration;

const BOUND: Duration = Duration::from_secs(10);

fn version(major: usize, minor: usize, patch: usize) -> Option<u32> {
    Some(Semver::new(major, minor, patch).to_u32().unwrap())
}

#[test]
fn requests_merge_until_taken() {
    let slot = RearmSlot::default();
    assert_eq!(slot.take(), None, "nothing pending");
    slot.request(true);
    slot.request(false);
    assert_eq!(
        slot.take(),
        Some(true),
        "a UDP request is not lost to a later one"
    );
    assert_eq!(slot.take(), None, "taken once");
}

fn terms(requested: bool, restore_udp: bool, budget: u32) -> Terms {
    Terms {
        requested,
        restore_udp,
        budget,
    }
}

#[test]
fn both_peers_agree_alike_and_a_request_earns_a_fresh_budget() {
    let cases = [
        // (mine, theirs, original) -> (udp, budget)
        (
            terms(false, false, 2),
            terms(false, false, 1),
            UdpMode::Enabled,
            (UdpMode::Disabled, 1),
        ),
        (
            terms(false, false, 0),
            terms(false, false, 3),
            UdpMode::Enabled,
            (UdpMode::Disabled, 0),
        ),
        (
            terms(true, false, 0),
            terms(false, false, 0),
            UdpMode::Enabled,
            (UdpMode::Disabled, RECOVERY_ATTEMPTS),
        ),
        (
            terms(false, false, 0),
            terms(true, true, 0),
            UdpMode::Enabled,
            (UdpMode::Enabled, RECOVERY_ATTEMPTS),
        ),
        (
            terms(true, true, 1),
            terms(false, false, 1),
            UdpMode::Disabled,
            (UdpMode::Disabled, RECOVERY_ATTEMPTS),
        ),
    ];
    for (mine, theirs, original, (udp_mode, budget)) in cases {
        let expected = Retry { udp_mode, budget };
        assert_eq!(
            agree(mine, theirs, original),
            expected,
            "{mine:?} vs {theirs:?}"
        );
        assert_eq!(
            agree(theirs, mine, original),
            expected,
            "the other side must agree"
        );
    }
}

/// Both peers park; one asks. Both wake, and both agree to restore UDP for the retry.
async fn one_side_asks(asker_is_initiator: bool, original: UdpMode) -> (Retry, Retry) {
    let (receiver, initiator) = create_streams_with_addrs().await;
    let (asker, other) = if asker_is_initiator {
        (initiator, receiver)
    } else {
        (receiver, initiator)
    };
    let (asker_slot, other_slot) = (RearmSlot::default(), RearmSlot::default());
    let side = |app: NetworkEndpoint, slot: RearmSlot| async move {
        assert!(park(&app, &slot).await, "parked endpoint failed");
        rendezvous(&app, true, &slot, original, 0).await.unwrap()
    };
    let asking = async {
        asker_slot.request(true);
        side(asker, asker_slot).await
    };
    tokio::time::timeout(BOUND, async {
        tokio::join!(asking, side(other, other_slot))
    })
    .await
    .expect("a request must wake both parked peers")
}

#[tokio::test]
async fn either_peer_can_wake_both_and_ask_for_udp() {
    for asker_is_initiator in [true, false] {
        let (a, b) = one_side_asks(asker_is_initiator, UdpMode::Enabled).await;
        let fresh = Retry {
            udp_mode: UdpMode::Enabled,
            budget: RECOVERY_ATTEMPTS,
        };
        assert_eq!((a, b), (fresh, fresh));
    }
}

#[tokio::test]
async fn udp_is_restored_only_for_a_connection_that_had_it() {
    let (a, b) = one_side_asks(true, UdpMode::Disabled).await;
    assert_eq!(
        (a.udp_mode, b.udp_mode),
        (UdpMode::Disabled, UdpMode::Disabled)
    );
}

#[tokio::test]
async fn parked_peers_stay_parked_until_asked() {
    let (receiver, initiator) = create_streams_with_addrs().await;
    let (a, b) = (RearmSlot::default(), RearmSlot::default());
    let both = async { tokio::join!(park(&initiator, &a), park(&receiver, &b)) };
    assert!(
        tokio::time::timeout(Duration::from_millis(200), both)
            .await
            .is_err(),
        "nobody asked, so nobody may wake"
    );
}

#[tokio::test]
async fn a_peer_that_does_not_park_only_syncs() {
    let (receiver, initiator) = create_streams_with_addrs().await;
    let slot = RearmSlot::default();
    slot.request(true);
    let other = RearmSlot::default();
    let (a, b) = tokio::time::timeout(BOUND, async {
        tokio::join!(
            rendezvous(&initiator, false, &slot, UdpMode::Enabled, 2),
            rendezvous(&receiver, false, &other, UdpMode::Enabled, 1)
        )
    })
    .await
    .unwrap();
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(
        (a.udp_mode, b.udp_mode),
        (UdpMode::Disabled, UdpMode::Disabled)
    );
    assert_eq!(
        (a.budget, b.budget),
        (2, 1),
        "each side keeps its own budget, as before"
    );
}

#[test]
fn an_upgrade_is_refused_when_nothing_can_carry_it() {
    let current = Some(*crate::constants::PROTOCOL_VERSION);
    assert!(refuse_upgrade(current, false, true).is_none());
    let code = |err: Option<NetworkError>| err.expect("refused").code;
    assert_eq!(
        code(refuse_upgrade(version(0, 12, 0), false, true)),
        ErrorCode::P2pUpgradeUnsupported
    );
    assert_eq!(
        code(refuse_upgrade(None, false, true)),
        ErrorCode::P2pUpgradeUnsupported
    );
    assert_eq!(
        code(refuse_upgrade(current, false, false)),
        ErrorCode::P2pUpgradeUnavailable
    );
    assert_eq!(
        code(refuse_upgrade(current, true, true)),
        ErrorCode::P2pUpgradeUnavailable
    );
}
