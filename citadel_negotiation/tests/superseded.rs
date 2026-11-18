//! §5.2: a plain rekey crossing the epoch round.

mod common;

use citadel_negotiation::schedule::{Action, Side, World};
use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::{NegotiationState, RenegotiationReason, Setting};
use citadel_types::crypto::SecurityLevel::{Extreme, Standard};
use common::{profile, states, world};

const BUDGET: usize = 500;

/// Supersedes every key round A issues, up to `times`, then lets the rest run.
fn supersede(times: usize) -> (World<KeyProfile>, usize) {
    let mut w = world(profile(Standard), true);
    w.apply(Action::Request(Side::A, profile(Extreme)));
    let mut superseded = 0;
    while !w.dropped && w.steps < BUDGET {
        if !w.rounds.is_empty() && superseded < times {
            w.apply(Action::PlainRekey);
            superseded += 1;
        } else if !w.net.is_empty() {
            w.apply(Action::Deliver(0));
        } else {
            break;
        }
    }
    assert!(
        w.steps < BUDGET,
        "the re-issue loop must end on its own (max_apply_attempts)"
    );
    w.run_to_quiescence(BUDGET).expect("quiescent");
    w.check(true).expect("invariants");
    (w, superseded)
}

#[test]
fn superseded_apply_reissues_then_succeeds() {
    let (w, superseded) = supersede(2);
    assert_eq!(superseded, 2);
    assert!(!w.dropped);
    for side in [Side::A, Side::B] {
        assert_eq!(*w.party(side).neg.current().1, profile(Extreme));
    }
}

#[test]
fn superseded_apply_reissues_then_falls_back() {
    let (w, superseded) = supersede(usize::MAX);
    assert_eq!(superseded, usize::from(common::policy().max_apply_attempts));
    assert!(w.dropped);
    let reason = RenegotiationReason::ApplyFailed(KeyProfile::ID);
    assert!(states(&w, Side::A)
        .iter()
        .any(|s| matches!(s, NegotiationState::FellBack { reason: r, .. } if *r == reason)));
}
