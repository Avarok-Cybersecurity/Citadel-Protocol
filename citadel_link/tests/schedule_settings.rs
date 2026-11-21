//! Settings changes on a live pair (§4, §4.4, §11.1): decided locally, carried out by the Leader,
//! never through the server for an in-band or on-path change.

mod common;

use citadel_link::schedule::{Action, Side, World};
use citadel_link::{
    LinkCommand, LinkEvent, LinkState, LossCause, PathTrigger, PunchReuse, RetireReason,
};
use citadel_types::crypto::SecurityLevel;
use common::*;

fn forks(w: &World, side: Side) -> usize {
    w.count(side, |c| matches!(c, LinkCommand::ForkPath { .. }))
}

fn path_reports(w: &World, side: Side) -> usize {
    w.outcomes(side).0
}

fn server_asks(w: &World, side: Side) -> usize {
    w.count(side, |c| matches!(c, LinkCommand::Rendezvous { .. }))
}

#[test]
fn both_raising_the_level_at_once_is_one_in_band_epoch_with_no_reconnect() {
    let mut w = up(ALL);
    w.apply(Action::AgreeBoth(
        settings(SecurityLevel::Extreme),
        settings(SecurityLevel::High),
    ));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    for side in [Side::A, Side::B] {
        assert_eq!(forks(&w, side), 0);
        assert_eq!(server_asks(&w, side), 1, "only the first meeting");
        assert_eq!(path_reports(&w, side), 1, "the path did not change");
        assert_eq!(
            w.party(side).core.settings(),
            settings(SecurityLevel::Extreme),
            "the merge never lowers"
        );
    }
}

#[test]
fn a_downgrade_moves_only_the_floor() {
    let mut w = up(ALL);
    w.apply(Action::Agree(settings(SecurityLevel::High)));
    w.run_to_quiescence(500).unwrap();
    let before = w.a.commands.len();
    w.apply(Action::Agree(settings(SecurityLevel::Standard)));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    assert_eq!(
        w.a.commands.len(),
        before,
        "no command at all: no reconnect on a downgrade"
    );
    assert_eq!(w.a.core.settings(), settings(SecurityLevel::Standard));
}

#[test]
fn a_kem_change_reseals_on_the_live_path_led_by_the_leader_only() {
    let mut w = up(ALL);
    let route_of = |w: &World, side| match w.state(side) {
        LinkState::Up { route, .. } => *route,
        other => panic!("{other:?}"),
    };
    let routes_before = [route_of(&w, Side::A), route_of(&w, Side::B)];
    w.apply(Action::Agree(other_kem(SecurityLevel::Standard)));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    assert_eq!(forks(&w, Side::A), 1, "the Leader forks the path");
    assert_eq!(forks(&w, Side::B), 0, "the Loser only answers");
    for (side, route_before) in [Side::A, Side::B].into_iter().zip(routes_before) {
        let LinkState::Up {
            incarnation, route, ..
        } = w.state(side)
        else {
            panic!();
        };
        assert_eq!(incarnation.n, 2, "a reseal is a new incarnation");
        assert_eq!(*route, route_before, "on the same route");
        assert_eq!(server_asks(&w, side), 1);
        let last = w
            .party(side)
            .events
            .iter()
            .rev()
            .find_map(|e| match e {
                LinkEvent::Path(o) => Some(o.clone()),
                _ => None,
            })
            .unwrap();
        assert!(matches!(last.trigger, PathTrigger::SettingsChange(_)));
        assert_eq!(last.punch, PunchReuse::ReusedSocket);
        let retired_old = w.count(side, |c| {
            matches!(c, LinkCommand::Retire { incarnation, reason: RetireReason::Superseded } if incarnation.n == 1)
        });
        assert_eq!(
            retired_old, 1,
            "{side:?}: the old incarnation is retired after the cutover"
        );
    }
}

#[test]
fn a_kem_change_with_a_legacy_peer_reestablishes() {
    let caps = citadel_link::PeerCaps {
        reseal: false,
        ..ALL
    };
    let mut w = up(caps);
    w.apply(Action::Agree(other_kem(SecurityLevel::Standard)));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    let LinkState::Up { incarnation, .. } = w.state(Side::A) else {
        panic!();
    };
    assert_eq!(incarnation.n, 2);
    assert_eq!(w.a.core.settings(), other_kem(SecurityLevel::Standard));
    let degraded: Vec<_> =
        w.a.events
            .iter()
            .filter_map(|e| match e {
                LinkEvent::Degraded(d) => Some(d.cause),
                _ => None,
            })
            .collect();
    assert_eq!(degraded, [LossCause::Settings]);
}

#[test]
fn a_drop_during_a_reseal_abandons_the_new_incarnation_and_heals_once() {
    let mut w = up(ALL);
    w.apply(Action::Agree(other_kem(SecurityLevel::Standard)));
    assert!(matches!(w.state(Side::A), LinkState::Resealing { .. }));
    w.apply(Action::Lose(LossCause::Transient));
    let reports_after_drop = path_reports(&w, Side::A);
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    for side in [Side::A, Side::B] {
        let abandoned = w.count(side, |c| {
            matches!(
                c,
                LinkCommand::Retire {
                    reason: RetireReason::Abandoned,
                    ..
                }
            )
        });
        assert_eq!(abandoned, 1, "{side:?}");
        let delivered = w.count(side, |c| matches!(c, LinkCommand::Deliver { .. }));
        assert_eq!(
            delivered, 2,
            "{side:?}: the first seal and the heal, never the abandoned one"
        );
    }
    assert_eq!(
        path_reports(&w, Side::A),
        reports_after_drop + 1,
        "one outcome for the heal"
    );
    assert_eq!(
        w.a.core.settings(),
        settings(SecurityLevel::Standard),
        "the abandoned value is the negotiator's to re-apply"
    );
}
