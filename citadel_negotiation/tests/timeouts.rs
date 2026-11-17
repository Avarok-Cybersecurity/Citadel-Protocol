//! P7: every non-idle state leaves on its deadline, and a lost frame cannot leave a side stuck.

mod common;

use citadel_negotiation::schedule::{Action, Side, World};
use citadel_negotiation::{Frame, NegotiationState, RejectReason, RenegotiationReason};
use common::{states, world, Tier};

fn lose_first_matching(w: &mut World<Tier>, pick: impl Fn(&Frame) -> bool) {
    let i = w
        .net
        .iter()
        .position(|f| pick(&f.envelope.frame))
        .expect("the frame is in flight");
    w.apply(Action::Lose(i));
}

fn fell_back(w: &World<Tier>, side: Side) -> Option<RenegotiationReason> {
    states(w, side).iter().find_map(|s| match s {
        NegotiationState::FellBack { reason, .. } => Some(*reason),
        _ => None,
    })
}

#[test]
fn timeouts_and_deadlines_proposing() {
    let mut w = world(Tier(0), true);
    w.apply(Action::Request(Side::A, Tier(1)));
    lose_first_matching(&mut w, |f| matches!(f, Frame::Propose { .. }));
    w.run_to_quiescence(100).expect("quiescent");
    w.check(true).expect("invariants");
    assert!(w.dropped);
    assert!(states(&w, Side::A).contains(&NegotiationState::Rejected {
        reason: RejectReason::TimedOut,
        proposed: Tier(1)
    }));
    assert_eq!(fell_back(&w, Side::A), Some(RenegotiationReason::Desync));
}

#[test]
fn timeouts_and_deadlines_applying() {
    let mut w = world(Tier(0), true);
    w.apply(Action::Request(Side::A, Tier(1)));
    w.apply(Action::Deliver(0));
    w.local.retain(|(side, _)| *side != Side::B); // B's local apply never finishes
    w.run_to_quiescence(100).expect("quiescent");
    w.check(true).expect("invariants");
    assert!(w.dropped);
    assert!(fell_back(&w, Side::B).is_some() || fell_back(&w, Side::A).is_some());
}

#[test]
fn timeouts_and_deadlines_confirming() {
    let mut w = world(Tier(0), true);
    w.apply(Action::Request(Side::A, Tier(1)));
    w.apply(Action::Deliver(0)); // B accepts and starts applying
    w.apply(Action::Deliver(0)); // A gets the Accept and starts applying
    let b_done = w
        .local
        .iter()
        .position(|(side, _)| *side == Side::B)
        .expect("B applying");
    w.apply(Action::LocalDone(b_done));
    lose_first_matching(&mut w, |f| matches!(f, Frame::Applied { .. })); // B's Applied is lost
    w.run_to_quiescence(100)
        .expect("a side waiting on a lost Applied must still leave");
    w.check(true).expect("invariants");
    assert!(w.dropped, "the confirming side gave up on its deadline");
    assert_eq!(
        fell_back(&w, Side::A),
        Some(RenegotiationReason::ApplyFailed(
            <Tier as citadel_negotiation::Setting>::ID
        ))
    );
}
