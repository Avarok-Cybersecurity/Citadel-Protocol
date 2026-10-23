use super::*;
use citadel_types::proto::{PathClasses, PlannedPath};

fn cfg(policy: TurnPolicy) -> TurnRelayConfig {
    TurnRelayConfig::new(vec![], policy)
}

fn shape(plan: &P2pPlan) -> Vec<(PathStage, Duration)> {
    plan.steps
        .iter()
        .map(|s| (s.step.stage(), s.timeout))
        .collect()
}

const D: PathStage = PathStage::Direct;
const T: PathStage = PathStage::Turn;
const LEGACY: Duration = Duration::from_secs(30);

/// (direct impossible, TURN policy, planned stages, plan kind)
type Row = (
    bool,
    Option<TurnPolicy>,
    Vec<(PathStage, Duration)>,
    PathPlanKind,
);

/// Without a stamped plan, every input plans exactly what `plan_p2p` planned before path
/// policies: the four plans DirectOnly, DirectThenRelay, RelayOnly and ServerOnly, 30 s a stage.
#[test]
fn without_a_stamped_plan_each_peer_plans_as_before() {
    let table: [Row; 6] = [
        (false, None, vec![(D, LEGACY)], PathPlanKind::DirectOnly),
        (true, None, vec![], PathPlanKind::ServerOnly),
        (
            false,
            Some(TurnPolicy::Fallback),
            vec![(D, LEGACY), (T, LEGACY)],
            PathPlanKind::DirectThenTurn,
        ),
        (
            true,
            Some(TurnPolicy::Fallback),
            vec![(T, LEGACY)],
            PathPlanKind::TurnOnly,
        ),
        (
            false,
            Some(TurnPolicy::RelayOnly),
            vec![(T, LEGACY)],
            PathPlanKind::TurnOnly,
        ),
        (
            true,
            Some(TurnPolicy::RelayOnly),
            vec![(T, LEGACY)],
            PathPlanKind::TurnOnly,
        ),
    ];
    for (direct_impossible, policy, steps, kind) in table {
        let plan = execution_plan(None, direct_impossible, policy.map(cfg));
        assert_eq!(shape(&plan), steps, "{direct_impossible} {policy:?}");
        assert_eq!(plan.kind(), kind, "{direct_impossible} {policy:?}");
        assert_eq!(
            shape(&plan_p2p(direct_impossible, policy.map(cfg))),
            steps,
            "plan_p2p itself is unchanged"
        );
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
    // The local NAT verdict and TURN policy no longer decide: the server already did.
    let executed = execution_plan(Some(&plan), true, Some(cfg(TurnPolicy::Fallback)));
    assert_eq!(
        shape(&executed),
        [(T, Duration::from_secs(7)), (D, Duration::from_secs(4))]
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
    let executed = execution_plan(Some(&plan), false, None);
    assert_eq!(shape(&executed), [(D, Duration::from_secs(5))]);
}

#[test]
fn a_stamped_plan_of_only_the_server_relay_tries_nothing() {
    let plan = stamped(vec![planned(PathKind::ServerRelay, 30)]);
    let executed = execution_plan(Some(&plan), false, Some(cfg(TurnPolicy::Fallback)));
    assert!(executed.is_server_only());
    assert_eq!(executed.kind(), PathPlanKind::ServerOnly);
}

#[test]
fn peer_relay_is_never_executed() {
    let plan = stamped(vec![
        planned(PathKind::PeerRelay, 5),
        planned(PathKind::ServerRelay, 30),
    ]);
    assert!(execution_plan(Some(&plan), false, None).is_server_only());
}
