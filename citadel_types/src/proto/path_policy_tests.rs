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

#[test]
fn the_owners_order_is_a_valid_policy() {
    let p = policy(owner_rules());
    let kinds: Vec<_> = p.rules().iter().map(|r| r.kind).collect();
    assert_eq!(kinds, PathKind::ALL.to_vec());
}

#[test]
fn every_kind_must_appear_exactly_once() {
    let mut missing = owner_rules();
    missing.retain(|r| r.kind != PathKind::Turn);
    assert_eq!(
        PathPolicy::new(missing, PathClasses::NONE),
        Err(PathPolicyError::MissingKind(PathKind::Turn))
    );
    let mut twice = owner_rules();
    twice.insert(0, rule(PathKind::Turn, false, PathClasses::NONE));
    assert_eq!(
        PathPolicy::new(twice, PathClasses::NONE),
        Err(PathPolicyError::DuplicateKind(PathKind::Turn))
    );
}

#[test]
fn timeouts_must_be_one_to_sixty_seconds() {
    for (timeout, ok) in [
        (Duration::from_millis(999), false),
        (SECS(1), true),
        (SECS(60), true),
        (Duration::from_millis(60_001), false),
    ] {
        let mut rules = owner_rules();
        rules[0].attempt_timeout = timeout;
        let result = PathPolicy::new(rules, PathClasses::NONE);
        assert_eq!(result.is_ok(), ok, "{timeout:?}: {result:?}");
        if !ok {
            assert_eq!(
                result,
                Err(PathPolicyError::TimeoutOutOfRange {
                    kind: PathKind::Direct,
                    timeout
                })
            );
        }
    }
}

#[test]
fn the_server_relay_must_be_enabled_for_control() {
    let mut disabled = owner_rules();
    disabled[3].enabled = false;
    assert_eq!(
        PathPolicy::new(disabled, PathClasses::NONE),
        Err(PathPolicyError::ServerRelayMustCarryControl)
    );
    let mut no_control = owner_rules();
    no_control[3].classes = PathClasses::of(&[PathClass::Msg]);
    assert_eq!(
        PathPolicy::new(no_control, PathClasses::NONE),
        Err(PathPolicyError::ServerRelayMustCarryControl)
    );
}

#[test]
fn every_class_is_carried_or_explicitly_denied() {
    // Media only on Direct, and Direct disabled: media has nowhere to go.
    let mut rules: Vec<_> = owner_rules()
        .into_iter()
        .map(|mut r| {
            r.classes = PathClasses::of(&[PathClass::Control, PathClass::Msg, PathClass::File]);
            r
        })
        .collect();
    rules[0] = rule(PathKind::Direct, false, PathClasses::ALL);
    assert_eq!(
        PathPolicy::new(rules.clone(), PathClasses::NONE),
        Err(PathPolicyError::ClassUncovered(PathClass::Media))
    );
    let media = PathClasses::of(&[PathClass::Media]);
    assert!(PathPolicy::new(rules.clone(), media).is_ok());
    // Denying a class that a path still carries is a contradiction.
    rules[1].classes = PathClasses::ALL;
    assert_eq!(
        PathPolicy::new(rules, media),
        Err(PathPolicyError::DeniedClassAllowed {
            class: PathClass::Media,
            kind: PathKind::PeerRelay
        })
    );
}

#[test]
fn a_rule_enabled_after_the_server_relay_is_refused() {
    let mut rules = owner_rules();
    let turn = rules.remove(2);
    rules.push(turn);
    assert_eq!(
        PathPolicy::new(rules.clone(), PathClasses::NONE),
        Err(PathPolicyError::UnreachableAfterServerRelay(PathKind::Turn))
    );
    rules[3].enabled = false;
    assert!(PathPolicy::new(rules, PathClasses::NONE).is_ok());
}

#[test]
fn a_policy_off_the_wire_is_validated_again() {
    let valid = policy(owner_rules());
    let bytes = bincode::serialize(&valid).unwrap();
    assert_eq!(bincode::deserialize::<PathPolicy>(&bytes).unwrap(), valid);
    // The same bytes with the server relay's control bit cleared: refused on read.
    let mut rules = owner_rules();
    rules[3].classes = PathClasses::of(&[PathClass::Msg, PathClass::File, PathClass::Media]);
    #[derive(serde::Serialize)]
    struct Raw {
        rules: Vec<PathRule>,
        denied: PathClasses,
    }
    let forged = bincode::serialize(&Raw {
        rules,
        denied: PathClasses::NONE,
    })
    .unwrap();
    assert!(bincode::deserialize::<PathPolicy>(&forged).is_err());
}
