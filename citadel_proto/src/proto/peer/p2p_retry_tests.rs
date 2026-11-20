use super::wait_for_shared_fall_back;
use crate::proto::peer::p2p_path::{CampaignEndGuard, P2pPath, P2pPathCell, P2pRoute};
use citadel_io::tokio;
use netbeam::sync::test_utils::create_streams_with_addrs;
use std::time::Duration;

const BOUND: Duration = Duration::from_secs(10);

/// A connection on its direct route, with a live campaign.
fn direct() -> (P2pPathCell, CampaignEndGuard) {
    let cell = P2pPathCell::server_relayed();
    let guard = CampaignEndGuard::start(cell.clone());
    cell.set(P2pRoute::Direct);
    (cell, guard)
}

/// One side loses the route and the other's transport never notices: the worst case of the two
/// QUIC idle timers telling the peers a whole idle period apart. Both still fall back together.
#[tokio::test]
async fn a_route_lost_on_one_side_falls_back_on_both() {
    let (receiver, initiator) = create_streams_with_addrs().await;
    let ((lost, _a), (unaware, _b)) = (direct(), direct());
    let cut_unaware = unaware.clone();
    let both = async {
        tokio::join!(
            wait_for_shared_fall_back(&lost, &initiator, || {
                panic!("the side that lost the route was told to cut it")
            }),
            wait_for_shared_fall_back(&unaware, &receiver, move || {
                cut_unaware.fall_back_to_server_relay()
            }),
            async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                lost.fall_back_to_server_relay();
            },
        )
    };
    let (lost_retries, unaware_retries, ()) = tokio::time::timeout(BOUND, both)
        .await
        .expect("the side whose transport did not notice never fell back");
    assert!(lost_retries && unaware_retries);
    assert_eq!(unaware.status().path, P2pPath::ServerRelay);
}

/// Both sides lose the route at once: whichever the select picks, both fall back, and the cut
/// on a route that is already gone changes nothing.
#[tokio::test]
async fn a_route_lost_on_both_sides_at_once_falls_back_once() {
    let (receiver, initiator) = create_streams_with_addrs().await;
    let ((a, _ga), (b, _gb)) = (direct(), direct());
    a.fall_back_to_server_relay();
    b.fall_back_to_server_relay();
    let (ca, cb) = (a.clone(), b.clone());
    let both = async {
        tokio::join!(
            wait_for_shared_fall_back(&a, &initiator, move || { ca.fall_back_to_server_relay() }),
            wait_for_shared_fall_back(&b, &receiver, move || { cb.fall_back_to_server_relay() }),
        )
    };
    let (ra, rb) = tokio::time::timeout(BOUND, both).await.unwrap();
    assert!(ra && rb);
}

/// While the route is up on both sides, neither wakes the other.
#[tokio::test]
async fn a_live_route_wakes_nobody() {
    let (receiver, initiator) = create_streams_with_addrs().await;
    let ((a, _ga), (b, _gb)) = (direct(), direct());
    let both = async {
        tokio::join!(
            wait_for_shared_fall_back(&a, &initiator, || panic!("cut a live route")),
            wait_for_shared_fall_back(&b, &receiver, || panic!("cut a live route")),
        )
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(300), both)
            .await
            .is_err(),
        "a route nobody lost ended"
    );
}
