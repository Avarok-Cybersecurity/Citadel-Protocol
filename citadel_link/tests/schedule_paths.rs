//! Routes, flaps, the server going away, and true closes (§3.2, §9.3, §11.1).

mod common;

use citadel_link::schedule::{Action, Side, World};
use citadel_link::{
    CloseReason, LinkCommand, LinkEvent, LinkState, LossCause, PathTrigger, PunchReuse, RouteKind,
};
use common::*;

fn degraded(w: &World, side: Side) -> Vec<LossCause> {
    w.party(side)
        .events
        .iter()
        .filter_map(|e| match e {
            LinkEvent::Degraded(d) => Some(d.cause),
            _ => None,
        })
        .collect()
}

fn closes(w: &World, side: Side) -> Vec<CloseReason> {
    w.party(side)
        .events
        .iter()
        .filter_map(|e| match e {
            LinkEvent::Closed(c) => Some(c.reason),
            _ => None,
        })
        .collect()
}

#[test]
fn a_lost_direct_route_falls_back_to_the_relay_and_rearms_without_degrading() {
    let mut w = up(ALL);
    w.apply(Action::Lose(LossCause::RouteLost));
    for side in [Side::A, Side::B] {
        assert_eq!(w.count(side, |c| *c == LinkCommand::FallBackToRelay), 1);
        let LinkState::Up { route, .. } = w.state(side) else {
            panic!();
        };
        assert_eq!(route.kind, RouteKind::ServerRelay);
    }
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    for side in [Side::A, Side::B] {
        assert!(
            degraded(&w, side).is_empty(),
            "a route change is not a degradation"
        );
        let LinkState::Up { route, .. } = w.state(side) else {
            panic!();
        };
        assert_eq!(
            route.kind,
            RouteKind::Direct,
            "{side:?}: back on a direct route"
        );
        let last = w.party(side).events.iter().rev().find_map(|e| match e {
            LinkEvent::Path(o) => Some(o.clone()),
            _ => None,
        });
        let last = last.unwrap();
        assert_eq!(
            last.trigger,
            PathTrigger::LinkLost {
                cause: LossCause::RouteLost
            }
        );
        assert_eq!(last.punch, PunchReuse::Fresh);
    }
}

#[test]
fn a_relayed_link_rearms_on_its_backoff_until_the_direct_path_works() {
    let mut w = world(ALL);
    w.apply(Action::DirectDown);
    w.apply(Action::Start(Side::A));
    w.apply(Action::Start(Side::B));
    w.run_to_quiescence(60).unwrap();
    for _ in 0..3 {
        w.apply(Action::Tick(Side::A));
        w.run_to_quiescence(60).unwrap();
    }
    let LinkState::Up { route, .. } = w.state(Side::A) else {
        panic!("{:?}", w.state(Side::A));
    };
    assert_eq!(route.kind, RouteKind::ServerRelay);
    let rearms = |w: &World| {
        w.count(Side::A, |c| {
            matches!(
                c,
                LinkCommand::OpenPath {
                    trigger: PathTrigger::Rearm,
                    ..
                }
            )
        })
    };
    assert_eq!(rearms(&w), 3, "one re-arm per wake");
    w.apply(Action::DirectUp);
    w.apply(Action::Tick(Side::A));
    w.run_to_quiescence(60).unwrap();
    let LinkState::Up { route, .. } = w.state(Side::A) else {
        panic!();
    };
    assert_eq!(route.kind, RouteKind::Direct);
    w.check().unwrap();
}

#[test]
fn a_flapping_link_holds_once_the_flap_budget_is_spent() {
    let mut w = up(ALL);
    for _ in 0..4 {
        w.apply(Action::Lose(LossCause::Transient));
        w.run_to_quiescence(500).unwrap();
        w.check().unwrap();
    }
    let causes = degraded(&w, Side::A);
    assert_eq!(causes.len(), 4);
    assert_eq!(
        causes.iter().filter(|c| **c == LossCause::Flapping).count(),
        1,
        "{causes:?}"
    );
    assert_eq!(causes[3], LossCause::Flapping);
    let opens: Vec<u64> =
        w.a.commands
            .iter()
            .filter_map(|c| match c {
                LinkCommand::OpenPath {
                    deadline, stage, ..
                } => Some(deadline.0 - stage.timeout.as_millis() as u64),
                _ => None,
            })
            .collect();
    assert!(
        *opens.last().unwrap() >= 20 * S,
        "the fourth heal waited the hold: {opens:?}"
    );
}

#[test]
fn with_the_server_down_a_direct_pair_heals_and_changes_settings_without_it() {
    let mut w = up(ALL);
    w.apply(Action::ServerDown);
    w.apply(Action::Lose(LossCause::Transient));
    w.run_to_quiescence(500).unwrap();
    w.apply(Action::Agree(settings(
        citadel_types::crypto::SecurityLevel::High,
    )));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    for side in [Side::A, Side::B] {
        let asks = w.count(side, |c| matches!(c, LinkCommand::Rendezvous { .. }));
        assert_eq!(
            asks, 1,
            "{side:?}: no server command after the first meeting"
        );
    }
}

#[test]
fn a_link_that_cannot_heal_gives_up_and_reports_one_close_each() {
    let mut w = up(ALL);
    w.apply(Action::ServerDown);
    w.apply(Action::DirectDown);
    w.apply(Action::Lose(LossCause::Transient));
    w.run_to_quiescence(2000).unwrap();
    w.check().unwrap();
    for side in [Side::A, Side::B] {
        let reasons = closes(&w, side);
        assert_eq!(reasons.len(), 1, "{side:?}: {reasons:?}");
        assert!(
            matches!(reasons[0], CloseReason::GaveUp { attempts: 6, .. }),
            "{reasons:?}"
        );
    }
}

#[test]
fn a_shutdown_retires_every_incarnation_and_the_peer_closes_too() {
    let mut w = up(ALL);
    w.apply(Action::Shutdown(Side::A));
    assert!(matches!(
        w.state(Side::A),
        LinkState::Closing { retiring: 1, .. }
    ));
    w.run_to_quiescence(500).unwrap();
    w.check().unwrap();
    assert_eq!(
        closes(&w, Side::A),
        [CloseReason::Local(citadel_link::ShutdownReason::Shutdown)]
    );
    assert_eq!(closes(&w, Side::B), [CloseReason::Peer(None)]);
    let LinkEvent::Closed(summary) = w.a.events.last().unwrap() else {
        panic!();
    };
    assert_eq!(summary.incarnations, 1);
}
