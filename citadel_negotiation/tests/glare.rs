//! §4.2: both sides propose in the same epoch.

mod common;

use citadel_negotiation::schedule::{Action, Side};
use citadel_negotiation::{NegotiationState, RejectReason, Setting};
use citadel_types::crypto::SecurityLevel::{Extreme, High, Reinforced, Standard};
use common::{applied_count, profile, states, world, world_with_minimums};

const BUDGET: usize = 200;

fn crossed<S: Setting>(
    mut w: citadel_negotiation::schedule::World<S>,
    a: S,
    b: S,
) -> citadel_negotiation::schedule::World<S> {
    w.apply(Action::Request(Side::A, a));
    w.apply(Action::Request(Side::B, b));
    w.run_to_quiescence(BUDGET).expect("quiescent");
    w.check(false).expect("invariants");
    w
}

#[test]
fn glare_both_raise() {
    let w = crossed(
        world(profile(Standard), true),
        profile(Extreme),
        profile(High),
    );
    assert!(!w.dropped, "an in-band raise never drops the connection");
    for side in [Side::A, Side::B] {
        assert_eq!(*w.party(side).neg.current().1, profile(Extreme));
        assert_eq!(applied_count(&w, side), 1);
    }
    assert_eq!(w.version, 1, "exactly one key round built the agreed epoch");
    let b = states(&w, Side::B);
    assert!(b.contains(&NegotiationState::Rejected {
        reason: RejectReason::Superseded,
        proposed: profile(High)
    }));
    assert!(b.contains(&NegotiationState::Accepted {
        agreed: profile(Extreme)
    }));
    assert!(!states(&w, Side::A)
        .iter()
        .any(|s| matches!(s, NegotiationState::Rejected { .. })));
}

#[test]
fn glare_raise_vs_lower() {
    // B may lower: its minimum is Standard. Glare still never lowers.
    let base = world_with_minimums(
        profile(Reinforced),
        profile(Reinforced),
        profile(Standard),
        false,
    );
    let w = crossed(base, profile(Extreme), profile(Standard));
    for side in [Side::A, Side::B] {
        assert_eq!(*w.party(side).neg.current().1, profile(Extreme));
    }
    let b = states(&w, Side::B);
    assert!(b.contains(&NegotiationState::Rejected {
        reason: RejectReason::Superseded,
        proposed: profile(Standard)
    }));
    assert_eq!(w.version, 1);
}

#[test]
fn glare_identical() {
    let w = crossed(world(profile(Standard), true), profile(High), profile(High));
    for side in [Side::A, Side::B] {
        assert_eq!(*w.party(side).neg.current().1, profile(High));
        assert_eq!(applied_count(&w, side), 1);
        assert!(!states(&w, side)
            .iter()
            .any(|s| matches!(s, NegotiationState::Rejected { .. })));
    }
    assert_eq!(w.version, 1, "identical proposals apply once");
}

#[test]
fn glare_where_both_lower_is_refused_on_both_sides() {
    let base = world_with_minimums(
        profile(Extreme),
        profile(Standard),
        profile(Standard),
        false,
    );
    let w = crossed(base, profile(High), profile(Reinforced));
    for side in [Side::A, Side::B] {
        assert_eq!(*w.party(side).neg.current().1, profile(Extreme));
        assert!(states(&w, side).iter().any(|s| matches!(
            s,
            NegotiationState::Rejected {
                reason: RejectReason::Crossed,
                ..
            }
        )));
    }
    assert_eq!(w.version, 0);
}
