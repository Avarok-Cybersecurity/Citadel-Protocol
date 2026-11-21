//! Heals on a peer pair, driven by the deterministic harness (§3.3, §6.2, §11.1).

mod common;

use citadel_link::schedule::{Action, Side};
use citadel_link::{
    LinkCommand, LinkEvent, LinkState, LossCause, PathTrigger, PeerCaps, PunchReuse,
};
use common::*;

fn outcomes(
    w: &citadel_link::schedule::World,
    side: Side,
) -> Vec<citadel_link::PathAttemptOutcome> {
    w.party(side)
        .events
        .iter()
        .filter_map(|e| match e {
            LinkEvent::Path(o) => Some(o.clone()),
            _ => None,
        })
        .collect()
}

fn degraded(w: &citadel_link::schedule::World, side: Side) -> Vec<LossCause> {
    w.party(side)
        .events
        .iter()
        .filter_map(|e| match e {
            LinkEvent::Degraded(d) => Some(d.cause),
            _ => None,
        })
        .collect()
}

fn rendezvous(w: &citadel_link::schedule::World, side: Side) -> usize {
    w.count(side, |c| matches!(c, LinkCommand::Rendezvous { .. }))
}

#[test]
fn the_first_establishment_reports_one_initial_outcome_on_each_side() {
    let w = up(ALL);
    for side in [Side::A, Side::B] {
        let all = outcomes(&w, side);
        assert_eq!(all.len(), 1, "{side:?}: {all:?}");
        assert_eq!(all[0].trigger, PathTrigger::Initial);
        assert_eq!(all[0].punch, PunchReuse::Fresh);
        assert_eq!(all[0].downtime, None);
        assert!(degraded(&w, side).is_empty());
    }
}

#[test]
fn a_transient_drop_reattaches_the_live_seal_with_no_server_and_one_outcome() {
    let mut w = up(ALL);
    let before = w.state(Side::A).clone();
    w.apply(Action::Lose(LossCause::Transient));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    let LinkState::Up { incarnation, .. } = (w.state(Side::A), before).0 else {
        panic!("A is not up");
    };
    assert_eq!(incarnation.n, 1, "a reattach keeps the incarnation");
    for side in [Side::A, Side::B] {
        let all = outcomes(&w, side);
        assert_eq!(all.len(), 2, "{side:?}: {all:?}");
        assert_eq!(all[1].punch, PunchReuse::Reattached, "{side:?}");
        assert!(
            all[1].downtime.is_some(),
            "{side:?}: a heal reports its downtime"
        );
        assert_eq!(degraded(&w, side), [LossCause::Transient], "{side:?}");
        assert_eq!(
            rendezvous(&w, side),
            1,
            "{side:?}: only the first meeting used the server"
        );
    }
}

#[test]
fn without_reattach_a_drop_reseals_on_the_punched_socket() {
    let caps = PeerCaps {
        reattach: false,
        ..ALL
    };
    let mut w = up(caps);
    w.apply(Action::Lose(LossCause::Transient));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    let LinkState::Up { incarnation, .. } = w.state(Side::B) else {
        panic!("B is not up");
    };
    assert_eq!(incarnation.n, 2, "a fresh seal is a new incarnation");
    let leader = outcomes(&w, Side::A);
    assert_eq!(leader[1].punch, PunchReuse::ReusedSocket);
    assert_eq!(rendezvous(&w, Side::A), 1);
}

#[test]
fn a_nat_change_on_a_migratable_route_rebinds_and_reports_migrated() {
    let mut w = up(ALL);
    w.apply(Action::NatChange(Side::A));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    let all = outcomes(&w, Side::A);
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].punch, PunchReuse::Migrated);
    assert_eq!(all[1].trigger, PathTrigger::NatChanged);
    assert!(degraded(&w, Side::A).is_empty(), "a rebind never degrades");
}

#[test]
fn a_nat_change_on_a_listener_route_heals_through_the_server_and_reattaches() {
    let mut w = up(ALL);
    w.apply(Action::NatChange(Side::B));
    w.apply(Action::Lose(LossCause::Transient));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    assert_eq!(degraded(&w, Side::B), [LossCause::NatChanged]);
    let b = outcomes(&w, Side::B);
    assert_eq!(b.last().unwrap().punch, PunchReuse::Reattached);
}

#[test]
fn a_peer_that_never_answers_backs_off_deterministically_and_the_link_gives_up() {
    let mut w = world(ALL);
    w.apply(Action::Start(Side::A));
    w.run_to_quiescence(500).unwrap();
    let LinkState::Closed { reason } = w.state(Side::A) else {
        panic!("not closed: {:?}", w.state(Side::A));
    };
    assert_eq!(
        *reason,
        citadel_link::CloseReason::Unreachable { attempts: 6 }
    );
    let starts: Vec<u64> = w
        .party(Side::A)
        .commands
        .iter()
        .filter_map(|c| match c {
            LinkCommand::Rendezvous { deadline, .. } => Some(deadline.0 - 10 * S),
            _ => None,
        })
        .collect();
    let gaps: Vec<u64> = starts.windows(2).map(|p| p[1] - p[0]).collect();
    assert_eq!(
        gaps,
        [S, 2 * S, 4 * S, 8 * S, 16 * S],
        "first_wait * 2^n, no jitter"
    );
    let closes = w
        .party(Side::A)
        .events
        .iter()
        .filter(|e| matches!(e, LinkEvent::Closed(_)))
        .count();
    assert_eq!(closes, 1);
}

#[test]
fn a_peer_coming_online_short_circuits_the_backoff() {
    let mut w = world(ALL);
    w.apply(Action::Start(Side::A));
    w.apply(Action::Resolve(Side::A, 0, true));
    let LinkState::Degraded { next_at, cause, .. } = w.state(Side::A).clone() else {
        panic!("not degraded: {:?}", w.state(Side::A));
    };
    assert_eq!(cause, LossCause::PeerOffline);
    assert!(next_at.unwrap() > w.now, "waits its backoff");
    w.apply(Action::Reachable(Side::A));
    let LinkState::Degraded { next_at, .. } = w.state(Side::A).clone() else {
        panic!();
    };
    assert_eq!(next_at, Some(w.now), "heals at once");
    w.apply(Action::Start(Side::B));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
}

#[test]
fn a_suspended_side_sets_no_wake_and_probes_once_on_resume() {
    let mut w = up(ALL);
    w.apply(Action::Lose(LossCause::Transient));
    w.apply(Action::Suspend(Side::A));
    w.apply(Action::Suspend(Side::B));
    assert_eq!(w.a.core.next_wake(), None);
    assert_eq!(w.b.core.next_wake(), None);
    w.apply(Action::Resume(Side::A));
    w.apply(Action::Resume(Side::B));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    assert_eq!(w.count(Side::A, |c| *c == LinkCommand::Probe), 1);
    assert_eq!(outcomes(&w, Side::A)[1].punch, PunchReuse::Reattached);
}

#[test]
fn past_the_grace_a_resumed_link_reseals_instead_of_reattaching() {
    let mut w = up(ALL);
    w.apply(Action::Lose(LossCause::Transient));
    w.apply(Action::Suspend(Side::A));
    w.apply(Action::Suspend(Side::B));
    w.now = citadel_link::Millis(w.now.0 + 301 * S);
    w.apply(Action::Resume(Side::A));
    w.apply(Action::Resume(Side::B));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    let last = outcomes(&w, Side::A).pop().unwrap();
    assert_ne!(last.punch, PunchReuse::Reattached);
    assert_eq!(last.incarnation.unwrap().n, 2);
}

#[test]
fn a_half_open_link_heals_when_the_peer_redials_into_it() {
    let mut w = up(ALL);
    let LinkState::Up { incarnation, .. } = *w.state(Side::A) else {
        panic!();
    };
    // Only A sees the drop; B learns of it from A's redial alone.
    w.step(
        Side::A,
        citadel_link::LinkInput::LinkLost {
            incarnation,
            cause: LossCause::Transient,
        },
    );
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    assert_eq!(degraded(&w, Side::B), [LossCause::Transient]);
}
