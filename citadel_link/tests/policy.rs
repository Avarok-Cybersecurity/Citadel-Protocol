//! `LinkPolicy` (§2.4, owner Q4): every bound required, none zero, no jitter.

mod common;

use std::time::Duration;

use citadel_link::{LinkPolicy, PolicyError, Role};
use common::*;

/// One way to break a policy.
type Breaks = fn(&mut LinkPolicy);

#[test]
fn validate_refuses_every_zero_wait_and_a_zero_factor() {
    assert_eq!(policy().validate(), Ok(()));
    let cases: Vec<(Breaks, PolicyError)> = vec![
        (
            |p| p.heal.backoff.first_wait = Duration::ZERO,
            PolicyError::ZeroWait("heal"),
        ),
        (
            |p| p.heal.backoff.factor = 0,
            PolicyError::ZeroFactor("heal"),
        ),
        (
            |p| p.heal.backoff.max_wait = Duration::from_millis(1),
            PolicyError::MaxBelowFirst("heal"),
        ),
        (|p| p.rearm.factor = 0, PolicyError::ZeroFactor("rearm")),
        (
            |p| p.heal.max_attempts = Some(0),
            PolicyError::ZeroMaxAttempts,
        ),
        (
            |p| p.heal.give_up_after = Some(Duration::ZERO),
            PolicyError::ZeroDeadline("give_up_after"),
        ),
        (
            |p| p.flap.window = Duration::ZERO,
            PolicyError::ZeroFlapWindow,
        ),
        (
            |p| p.flap.hold = Duration::ZERO,
            PolicyError::ZeroWait("flap.hold"),
        ),
        (
            |p| p.reattach_grace = Duration::ZERO,
            PolicyError::ZeroWait("reattach_grace"),
        ),
        (
            |p| p.loser_redial_wait = Duration::ZERO,
            PolicyError::ZeroWait("loser_redial_wait"),
        ),
        (
            |p| p.probe_interval = Some(Duration::ZERO),
            PolicyError::ZeroWait("probe_interval"),
        ),
        (
            |p| p.seal_deadline = Duration::ZERO,
            PolicyError::ZeroDeadline("seal_deadline"),
        ),
        (
            |p| p.rendezvous_deadline = Duration::ZERO,
            PolicyError::ZeroDeadline("rendezvous_deadline"),
        ),
        (
            |p| p.settings_deadline = Duration::ZERO,
            PolicyError::ZeroDeadline("settings_deadline"),
        ),
        (
            |p| p.direct_rendezvous_budget = Duration::ZERO,
            PolicyError::ZeroDeadline("direct_rendezvous_budget"),
        ),
    ];
    for (break_it, expected) in cases {
        let mut p = policy();
        break_it(&mut p);
        assert_eq!(p.validate(), Err(expected));
    }
}

#[test]
fn a_core_refuses_an_invalid_policy() {
    let mut cfg = peer(1, 2, ALL);
    cfg.policy.heal.backoff.factor = 0;
    assert!(matches!(
        citadel_link::LinkCore::new(cfg),
        Err(citadel_link::ConfigError::Policy(PolicyError::ZeroFactor(
            "heal"
        )))
    ));
    assert!(matches!(
        citadel_link::LinkCore::new(peer(3, 3, ALL)),
        Err(citadel_link::ConfigError::NoRole)
    ));
    let mut bad = server(ALL);
    bad.plan = None;
    assert_eq!(
        citadel_link::LinkCore::new(bad).err(),
        Some(citadel_link::ConfigError::ServerPlan)
    );
}

#[test]
fn the_backoff_is_deterministic_capped_and_the_loser_waits_a_fixed_offset() {
    let p = policy();
    let leader: Vec<_> = (1..=8)
        .map(|n| p.heal_wait(n, Role::Leader).as_secs())
        .collect();
    assert_eq!(
        leader,
        [0, 1, 2, 4, 8, 16, 30, 30],
        "first heal at once, then doubling, capped"
    );
    let loser: Vec<_> = (1..=8)
        .map(|n| p.heal_wait(n, Role::Loser).as_secs())
        .collect();
    assert_eq!(loser, [2, 3, 4, 6, 10, 18, 32, 32]);
    assert_eq!(
        p.heal.backoff.wait(u32::MAX),
        p.heal.backoff.max_wait,
        "no overflow"
    );
}
