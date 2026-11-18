//! §4.2(5): a cancel that crosses an accept loses.

mod common;

use citadel_negotiation::schedule::{Action, Side, World};
use citadel_negotiation::{Epoch, Frame, NegotiationState, Setting};
use citadel_types::crypto::SecurityLevel::{Extreme, Standard};
use common::{profile, states, world, Tier};

fn cancel_after_the_peer_accepted<S: Setting>(mut w: World<S>, value: S) -> World<S> {
    w.apply(Action::Request(Side::A, value));
    w.apply(Action::Deliver(0)); // B accepts: its Accept is now in flight to A
    w.apply(Action::Cancel(Side::A)); // A's cancel crosses that Accept
    assert!(matches!(
        w.net.last().map(|f| &f.envelope.frame),
        Some(Frame::Cancel { .. })
    ));
    let cancel = w.net.len() - 1;
    w.apply(Action::Deliver(cancel)); // B sees the cancel first, while applying
    w.run_to_quiescence(200).expect("quiescent");
    w.check(true).expect("invariants");
    w
}

fn assert_cancel_lost<S: Setting>(w: &World<S>, value: &S) {
    assert!(!w.dropped, "the cancel must not cost the connection");
    for side in [Side::A, Side::B] {
        assert_eq!(w.party(side).neg.current(), (Epoch(1), value));
    }
    assert!(states(w, Side::A).contains(&NegotiationState::Applied {
        agreed: value.clone(),
        version: w
            .party(Side::A)
            .events
            .iter()
            .find_map(|e| match &e.state {
                NegotiationState::Applied { version, .. } => Some(*version),
                _ => None,
            })
            .flatten(),
    }));
}

#[test]
fn cancel_crossing_accept_loses() {
    let w = cancel_after_the_peer_accepted(world(Tier(0), true), Tier(2));
    assert_cancel_lost(&w, &Tier(2));
}

#[test]
fn cancel_crossing_accept_loses_on_a_key_epoch() {
    let w = cancel_after_the_peer_accepted(world(profile(Standard), true), profile(Extreme));
    assert_cancel_lost(&w, &profile(Extreme));
}

#[test]
fn a_cancel_answered_by_a_reject_leaves_both_idle() {
    let mut w = common::world_with_minimums(Tier(1), Tier(0), Tier(1), false);
    w.apply(Action::Request(Side::A, Tier(0))); // B's minimum refuses the lowering
    w.apply(Action::Cancel(Side::A));
    w.run_to_quiescence(200).expect("quiescent");
    w.check(false).expect("invariants");
    for side in [Side::A, Side::B] {
        assert_eq!(w.party(side).neg.current(), (Epoch(0), &Tier(1)));
    }
}
