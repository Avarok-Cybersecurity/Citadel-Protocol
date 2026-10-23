use super::*;
use crate::proto::peer::p2p_path::{P2pPath, P2pRoute};
use crate::proto::peer::p2p_plan::{plan_p2p, P2pPlan};
use citadel_wire::nat_identification::NatType;
use citadel_wire::udp_traversal::turn_relay::{TurnPolicy, TurnRelayConfig};
use std::time::Duration;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn context(plan: &P2pPlan, direct_impossible: bool) -> OutcomeContext {
    let nat = NatType::default().class();
    OutcomeContext::new(9, plan, direct_impossible, nat, nat)
}

fn turn(policy: TurnPolicy) -> P2pPlan {
    plan_p2p(false, Some(TurnRelayConfig::new(vec![], policy)))
}

fn stage(stage: PathStage, result: Result<(), StageFailure>, elapsed: Duration) -> StageOutcome {
    tried(stage, result, elapsed)
}

#[test]
fn a_direct_win_reports_the_path_and_its_time_to_connect() {
    let ctx = context(&plan_p2p(false, None), false);
    let report = AttemptReport {
        stages: vec![stage(PathStage::Direct, Ok(()), ms(700))],
        route: Some(P2pRoute::Direct),
    };
    let outcome = ctx.outcome(1, ms(300), report);
    assert_eq!(outcome.path, P2pPath::Direct);
    assert_eq!(outcome.plan, PathPlanKind::DirectOnly);
    assert_eq!(outcome.time_to_connect(), Some(ms(1000)));
    assert_eq!(
        outcome.stages,
        vec![
            stage(PathStage::Coordination, Ok(()), ms(300)),
            stage(PathStage::Direct, Ok(()), ms(700)),
            stage(PathStage::Turn, Err(StageFailure::NotConfigured), ms(0)),
        ],
        "every stage, in order, with the reason TURN was not tried"
    );
}

#[test]
fn a_failed_punch_then_a_turn_win_reports_both_stages() {
    let ctx = context(&turn(TurnPolicy::Fallback), false);
    let report = AttemptReport {
        stages: vec![
            stage(PathStage::Direct, Err(StageFailure::Timeout), ms(30_000)),
            stage(PathStage::Turn, Ok(()), ms(900)),
        ],
        route: Some(P2pRoute::Turn { relayed_both: true }),
    };
    let outcome = ctx.outcome(2, ms(0), report);
    assert_eq!((outcome.path, outcome.relayed_both), (P2pPath::Turn, true));
    assert_eq!(outcome.plan, PathPlanKind::DirectThenTurn);
    assert_eq!(outcome.attempt, 2);
    assert_eq!(
        outcome.failure(PathStage::Direct),
        Some(StageFailure::Timeout)
    );
    assert_eq!(outcome.failure(PathStage::Turn), None);
}

#[test]
fn a_relay_only_plan_says_why_the_punch_was_not_tried() {
    let by_policy = context(&turn(TurnPolicy::RelayOnly), false);
    let by_nat = context(&turn(TurnPolicy::RelayOnly), true);
    let failed_turn = || AttemptReport {
        stages: vec![stage(
            PathStage::Turn,
            Err(StageFailure::AllocationFailed),
            ms(5),
        )],
        route: None,
    };
    let outcome = by_policy.outcome(1, ms(1), failed_turn());
    assert_eq!(outcome.path, P2pPath::ServerRelay);
    assert_eq!(outcome.time_to_connect(), None);
    assert_eq!(
        outcome.failure(PathStage::Direct),
        Some(StageFailure::SkippedByPolicy)
    );
    assert_eq!(
        outcome.failure(PathStage::Turn),
        Some(StageFailure::AllocationFailed)
    );
    let outcome = by_nat.outcome(1, ms(1), failed_turn());
    assert_eq!(
        outcome.failure(PathStage::Direct),
        Some(StageFailure::NatIncompatible)
    );
}

#[test]
fn a_server_only_plan_reports_both_reasons_without_an_attempt() {
    let ctx = context(&plan_p2p(true, None), true);
    let outcome = ctx.outcome(1, ms(40), AttemptReport::nothing_attached(vec![]));
    assert_eq!(outcome.plan, PathPlanKind::ServerOnly);
    assert_eq!(outcome.path, P2pPath::ServerRelay);
    assert_eq!(
        outcome.failure(PathStage::Direct),
        Some(StageFailure::NatIncompatible)
    );
    assert_eq!(
        outcome.failure(PathStage::Turn),
        Some(StageFailure::NotConfigured)
    );
}

#[test]
fn peers_that_do_not_meet_report_only_the_coordination_failure() {
    let ctx = context(&plan_p2p(false, None), false);
    let outcome = ctx.unmet(4, StageFailure::Timeout, ms(30_000));
    assert_eq!(outcome.attempt, 4);
    assert_eq!(outcome.path, P2pPath::ServerRelay);
    assert_eq!(
        outcome.stages,
        vec![stage(
            PathStage::Coordination,
            Err(StageFailure::Timeout),
            ms(30_000)
        )]
    );
}

#[test]
fn a_stage_failure_is_classified_by_its_caller() {
    let io: std::io::Result<()> = Err(std::io::Error::other("refused"));
    let err = io.at(StageFailure::AllocationFailed).unwrap_err();
    assert_eq!(err.failure, StageFailure::AllocationFailed);
    assert!(err.to_string().contains("refused"));
}

#[test]
fn a_published_outcome_reaches_every_reader_of_the_cell() {
    let cell = crate::proto::peer::p2p_path::P2pPathCell::server_relayed();
    let mut changes = cell.outcomes();
    assert!(cell.last_outcome().is_none());
    let ctx = context(&plan_p2p(false, None), false);
    let report = AttemptReport::nothing_attached(vec![stage(
        PathStage::Direct,
        Err(StageFailure::PunchFailed),
        ms(10),
    )]);
    cell.record_outcome(ctx.outcome(1, ms(1), report));
    assert!(changes.has_changed().unwrap());
    let seen = changes.borrow_and_update().clone().unwrap();
    assert_eq!(
        seen.failure(PathStage::Direct),
        Some(StageFailure::PunchFailed)
    );
    assert_eq!(cell.last_outcome(), Some(seen));
}
