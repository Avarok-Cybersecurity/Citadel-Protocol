//! Heals through the shell: a lost direct route, a half-open link (§16), and two ends that saw
//! the same drop, where the Leader redials and the Loser answers instead of crossing its dial.

use std::sync::atomic::Ordering;

use citadel_link::{
    Incarnation, LinkInput, LossCause, Millis, PathStage, PathTrigger, RetireReason, RouteKind,
};

use super::Harness;

fn up(local: u64, peer: u64) -> Harness {
    let mut h = Harness::new(local, peer);
    h.start();
    assert_eq!(h.up_on(), Some(RouteKind::Direct));
    h
}

/// Every path this side opened: a first heal reuses its plan without a rendezvous (§3.3), so
/// an attempt is counted by its `OpenPath`, never by its `Rendezvous`.
fn dials(h: &Harness) -> usize {
    h.opened().len()
}

fn live(h: &Harness) -> Incarnation {
    match h.m.state() {
        citadel_link::LinkState::Up { incarnation, .. } => *incarnation,
        other => panic!("not up: {other:?}"),
    }
}

#[test]
fn a_lost_direct_route_falls_back_and_punches_again_without_degrading() {
    let mut h = up(1, 2);
    let incarnation = live(&h);
    h.input(LinkInput::LinkLost {
        incarnation,
        cause: LossCause::RouteLost,
    });
    assert_eq!(
        h.ports.fallbacks.load(Ordering::SeqCst),
        1,
        "traffic moved to the relay"
    );
    assert_eq!(
        h.opened(),
        vec![PathStage::Direct, PathStage::Direct],
        "a fresh punch"
    );
    assert_eq!(h.up_on(), Some(RouteKind::Direct), "back on a direct route");
    assert_eq!(
        live(&h),
        incarnation,
        "the same incarnation: the seal survived the route"
    );
    assert_eq!(h.degraded(), 0);
    let last = h.paths().pop().expect("an outcome for the new route");
    assert_eq!(
        last.trigger,
        PathTrigger::LinkLost {
            cause: LossCause::RouteLost
        }
    );
}

#[test]
fn a_half_open_link_degrades_then_answers_the_peers_redial() {
    let mut h = up(2, 1);
    let held = live(&h);
    let offered = held.next().expect("a next incarnation");
    h.offer(offered);
    assert_eq!(
        h.degraded(),
        1,
        "the half-open link is reported degraded once"
    );
    assert_eq!(
        live(&h),
        offered,
        "the link is up again as the incarnation the peer sealed"
    );
    assert!(
        h.script
            .retired
            .lock()
            .contains(&(held, RetireReason::Lost(LossCause::Transient))),
        "the half-open incarnation is retired as lost: {:?}",
        h.script.retired.lock()
    );
    assert_eq!(
        h.script.opened.lock().len(),
        1,
        "the responder opened no path of its own"
    );
    let last = h.paths().pop().expect("an outcome for the heal");
    assert_eq!(last.trigger, PathTrigger::PeerInitiated);
}

#[test]
fn after_a_drop_both_saw_the_leader_redials_at_once_and_the_loser_waits() {
    for (local, peer, waits) in [(1, 2, false), (2, 1, true)] {
        let mut h = up(local, peer);
        let incarnation = live(&h);
        let before = dials(&h);
        h.input(LinkInput::LinkLost {
            incarnation,
            cause: LossCause::Transient,
        });
        let redialled = dials(&h) > before;
        assert_eq!(
            redialled, !waits,
            "CID {local}: the Leader redials at once, the Loser waits"
        );
        if waits {
            // `loser_redial_wait` (2 s) is the Loser's deterministic offset.
            h.tick_to(Millis(1_999));
            assert_eq!(dials(&h), before, "no redial inside the offset");
            h.tick_to(Millis(2_000));
            assert!(dials(&h) > before, "the Loser redials after it");
        }
    }
}

#[test]
fn a_loser_answers_a_leader_that_healed_first_and_never_crosses_its_dial() {
    let mut h = up(2, 1);
    let incarnation = live(&h);
    let before = dials(&h);
    h.input(LinkInput::LinkLost {
        incarnation,
        cause: LossCause::Transient,
    });
    h.tick_to(Millis(1_000));
    h.offer(incarnation.next().expect("a next incarnation"));
    assert_eq!(
        h.up_on(),
        Some(RouteKind::Direct),
        "healed as the responder"
    );
    h.tick_to(Millis(10_000));
    assert_eq!(
        dials(&h),
        before,
        "the Loser never dialled: no crossed dial to fold"
    );
}
