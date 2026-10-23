use super::path_plan::*;
use super::path_policy::*;
use std::time::Duration;

const SECS: fn(u64) -> Duration = Duration::from_secs;

fn rule(kind: PathKind, enabled: bool, classes: PathClasses) -> PathRule {
    PathRule {
        kind,
        enabled,
        attempt_timeout: SECS(10),
        cost_weight: 1,
        classes,
    }
}

/// The owner's order: Direct, PeerRelay, Turn, ServerRelay; everything allowed everywhere.
fn owner_rules() -> Vec<PathRule> {
    PathKind::ALL
        .into_iter()
        .map(|k| rule(k, true, PathClasses::ALL))
        .collect()
}

fn policy(rules: Vec<PathRule>) -> PathPolicy {
    PathPolicy::new(rules, PathClasses::NONE).expect("valid policy")
}

const OPEN: PathOffer = PathOffer {
    restrictions: PathRestrictions::NONE,
    turn_ready: true,
};
const FEASIBLE: PairFeasibility = PairFeasibility {
    direct: true,
    forwarder: None,
};

fn kinds(plan: &EffectivePlan) -> Vec<PathKind> {
    plan.paths.iter().map(|p| p.kind).collect()
}

#[test]
fn the_plan_keeps_policy_order_and_drops_peer_relay_without_a_forwarder() {
    let plan = effective_plan(&policy(owner_rules()), &OPEN, &OPEN, FEASIBLE);
    assert_eq!(
        kinds(&plan),
        [PathKind::Direct, PathKind::Turn, PathKind::ServerRelay]
    );
    assert_eq!(plan.forwarder, None);
    let upgrades: Vec<_> = plan.upgrades().map(|p| p.kind).collect();
    assert_eq!(upgrades, [PathKind::Direct, PathKind::Turn]);
}

#[test]
fn the_plan_intersects_both_peers_restrictions_nat_and_turn() {
    let p = policy(owner_rules());
    let hide_ip = PathOffer {
        restrictions: PathRestrictions::denying(&[PathKind::Direct, PathKind::PeerRelay]).unwrap(),
        turn_ready: true,
    };
    let no_turn = PathOffer {
        turn_ready: false,
        ..OPEN
    };
    let nat_blocked = PairFeasibility {
        direct: false,
        ..FEASIBLE
    };
    for (a, b, pair, want) in [
        (
            hide_ip,
            OPEN,
            FEASIBLE,
            vec![PathKind::Turn, PathKind::ServerRelay],
        ),
        (
            OPEN,
            no_turn,
            FEASIBLE,
            vec![PathKind::Direct, PathKind::ServerRelay],
        ),
        (
            OPEN,
            OPEN,
            nat_blocked,
            vec![PathKind::Turn, PathKind::ServerRelay],
        ),
        (hide_ip, no_turn, FEASIBLE, vec![PathKind::ServerRelay]),
    ] {
        let plan = effective_plan(&p, &a, &b, pair);
        assert_eq!(kinds(&plan), want, "{a:?} {b:?} {pair:?}");
        assert_eq!(plan, effective_plan(&p, &b, &a, pair), "must be symmetric");
    }
}

#[test]
fn a_planned_path_carries_its_rule_timeout_and_classes() {
    let mut rules = owner_rules();
    rules[0].attempt_timeout = SECS(5);
    rules[2].attempt_timeout = SECS(20);
    rules[3].classes = PathClasses::of(&[PathClass::Control, PathClass::Msg, PathClass::File]);
    let plan = effective_plan(&policy(rules), &OPEN, &OPEN, FEASIBLE);
    let timeouts: Vec<_> = plan.upgrades().map(|p| p.attempt_timeout).collect();
    assert_eq!(timeouts, [SECS(5), SECS(20)]);
    assert!(!plan
        .classes_on(PathKind::ServerRelay)
        .contains(PathClass::Media));
    assert!(plan.classes_on(PathKind::Direct).contains(PathClass::Media));
    assert_eq!(plan.classes_on(PathKind::PeerRelay), PathClasses::NONE);
}

#[test]
fn a_forwarder_is_planned_only_with_peer_relay() {
    let pair = PairFeasibility {
        direct: false,
        forwarder: Some(7),
    };
    let plan = effective_plan(&policy(owner_rules()), &OPEN, &OPEN, pair);
    assert_eq!(plan.forwarder, Some(7));
    let refuse = PathOffer {
        restrictions: PathRestrictions::denying(&[PathKind::PeerRelay]).unwrap(),
        ..OPEN
    };
    let plan = effective_plan(&policy(owner_rules()), &refuse, &OPEN, pair);
    assert_eq!(plan.forwarder, None);
}

#[test]
fn the_server_relay_cannot_be_refused() {
    assert_eq!(
        PathRestrictions::denying(&[PathKind::ServerRelay]),
        Err(PathPolicyError::ServerRelayMustCarryControl)
    );
}

#[test]
fn class_sets_combine() {
    let a = PathClasses::of(&[PathClass::Msg, PathClass::File]);
    let b = PathClasses::of(&[PathClass::File, PathClass::Media]);
    assert_eq!(a.intersection(b), PathClasses::of(&[PathClass::File]));
    assert_eq!(a.union(b).iter().count(), 3);
    assert!(PathClasses::NONE.is_empty());
    assert!(!PathClasses::ALL.is_empty());
}
