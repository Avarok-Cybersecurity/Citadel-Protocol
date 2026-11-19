//! The plan (moved from `citadel_proto`'s `p2p_plan_tests`): without a stamped plan each peer
//! plans exactly as before path policies; a stamped plan is walked in order. Every P2P plan now
//! ends on the server relay, which the core opens as its last stage.

use std::time::Duration;

use citadel_link::plan::{execution_plan, plan_p2p, LEGACY_DIRECT_TIMEOUT, LEGACY_TURN_TIMEOUT};
use citadel_link::{PathPlanKind, PathStage, StageFailure, TurnConfig};
use citadel_types::proto::{EffectivePlan, PathClasses, PathKind, PlannedPath};

struct Turn(bool);

impl TurnConfig for Turn {
    fn relay_only(&self) -> bool {
        self.0
    }
}

const D: PathStage = PathStage::Direct;
const T: PathStage = PathStage::Turn;
const R: PathStage = PathStage::Relay;
const LEGACY: Duration = Duration::from_secs(30);
const RELAY: Duration = Duration::from_secs(10);

fn shape(plan: &citadel_link::PathPlan) -> Vec<(PathStage, Duration)> {
    plan.stages.iter().map(|s| (s.stage, s.timeout)).collect()
}

#[test]
fn without_a_stamped_plan_each_peer_plans_as_before() {
    type Row = (bool, Option<bool>, Vec<(PathStage, Duration)>, PathPlanKind);
    let rows: [Row; 6] = [
        (
            false,
            None,
            vec![(D, LEGACY), (R, RELAY)],
            PathPlanKind::DirectOnly,
        ),
        (true, None, vec![(R, RELAY)], PathPlanKind::ServerOnly),
        (
            false,
            Some(false),
            vec![(D, LEGACY), (T, LEGACY), (R, RELAY)],
            PathPlanKind::DirectThenTurn,
        ),
        (
            true,
            Some(false),
            vec![(T, LEGACY), (R, RELAY)],
            PathPlanKind::TurnOnly,
        ),
        (
            false,
            Some(true),
            vec![(T, LEGACY), (R, RELAY)],
            PathPlanKind::TurnOnly,
        ),
        (
            true,
            Some(true),
            vec![(T, LEGACY), (R, RELAY)],
            PathPlanKind::TurnOnly,
        ),
    ];
    for (impossible, relay_only, stages, kind) in rows {
        let turn = relay_only.map(Turn);
        let plan = execution_plan(None, impossible, turn.as_ref(), RELAY);
        assert_eq!(shape(&plan), stages, "{impossible} {relay_only:?}");
        assert_eq!(plan.kind(), kind, "{impossible} {relay_only:?}");
        assert_eq!(plan, plan_p2p(impossible, turn.as_ref(), RELAY));
    }
    assert_eq!(
        (LEGACY_DIRECT_TIMEOUT, LEGACY_TURN_TIMEOUT),
        (LEGACY, LEGACY)
    );
}

fn planned(kind: PathKind, secs: u64) -> PlannedPath {
    PlannedPath {
        kind,
        attempt_timeout: Duration::from_secs(secs),
        classes: PathClasses::ALL,
    }
}

fn stamped(paths: Vec<PlannedPath>) -> EffectivePlan {
    EffectivePlan {
        paths,
        forwarder: None,
    }
}

#[test]
fn a_stamped_plan_is_walked_in_order_with_each_paths_timeout() {
    let plan = stamped(vec![
        planned(PathKind::Turn, 7),
        planned(PathKind::Direct, 4),
        planned(PathKind::ServerRelay, 30),
    ]);
    let executed = execution_plan(Some(&plan), true, Some(&Turn(false)), RELAY);
    assert_eq!(
        shape(&executed),
        [
            (T, Duration::from_secs(7)),
            (D, Duration::from_secs(4)),
            (R, RELAY)
        ]
    );
    assert_eq!(executed.kind(), PathPlanKind::TurnThenDirect);
}

#[test]
fn a_stamped_turn_step_needs_this_peers_turn_config() {
    let plan = stamped(vec![
        planned(PathKind::Direct, 5),
        planned(PathKind::Turn, 9),
        planned(PathKind::ServerRelay, 30),
    ]);
    let executed = execution_plan::<Turn>(Some(&plan), false, None, RELAY);
    assert_eq!(shape(&executed), [(D, Duration::from_secs(5)), (R, RELAY)]);
    let skipped = executed.not_tried();
    assert_eq!(skipped.len(), 1);
    assert_eq!(
        (skipped[0].stage, skipped[0].result),
        (T, Err(StageFailure::NotConfigured))
    );
}

#[test]
fn what_a_plan_does_not_try_says_why() {
    let impossible = plan_p2p::<Turn>(true, None, RELAY);
    let reasons: Vec<_> = impossible
        .not_tried()
        .iter()
        .map(|s| (s.stage, s.result))
        .collect();
    assert_eq!(
        reasons,
        [
            (D, Err(StageFailure::NatIncompatible)),
            (T, Err(StageFailure::NotConfigured))
        ]
    );
    let relay_only = plan_p2p(false, Some(&Turn(true)), RELAY);
    let reasons: Vec<_> = relay_only
        .not_tried()
        .iter()
        .map(|s| (s.stage, s.result))
        .collect();
    assert_eq!(reasons, [(D, Err(StageFailure::SkippedByPolicy))]);
    let server = citadel_link::PathPlan::server(Duration::from_secs(4));
    assert!(server.not_tried().is_empty());
    assert_eq!(server.kind(), PathPlanKind::ServerDial);
}
