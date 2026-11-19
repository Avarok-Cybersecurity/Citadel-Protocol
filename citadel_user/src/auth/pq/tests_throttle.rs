//! The throttle core: lockouts, their doubling, the per-account key, recovery's double cost, the
//! start limit and the bounded table. Every decision is a function of the calls and `now`.

use super::throttle::{Attempt, Decision, SignInThrottle, ThrottlePolicy};
use std::net::IpAddr;

const MIN: u64 = 60 * 1000;
const USER: &str = "alice";

fn ip(text: &str) -> Option<IpAddr> {
    Some(text.parse().unwrap())
}

fn throttle() -> SignInThrottle {
    SignInThrottle::new(ThrottlePolicy::RECOMMENDED).unwrap()
}

fn fail(t: &mut SignInThrottle, source: Option<IpAddr>, attempt: Attempt, times: u32, now: u64) {
    for _ in 0..times {
        assert_eq!(t.admit(USER, source, attempt, now), Decision::Admit);
        t.record_failure(USER, source, attempt, now);
    }
}

#[test]
fn five_failures_lock_the_key_for_a_minute_doubling_to_an_hour() {
    let mut t = throttle();
    let src = ip("203.0.113.7");
    let mut now = 0;
    for expected in [1, 2, 4, 8, 16, 32, 60, 60] {
        fail(&mut t, src, Attempt::SignIn, 5, now);
        assert_eq!(t.admit(USER, src, Attempt::SignIn, now), Decision::Refuse);
        let until = now + expected * MIN;
        assert_eq!(
            t.admit(USER, src, Attempt::SignIn, until - 1),
            Decision::Refuse
        );
        // A new window, so the start limit does not decide here.
        now = until + ThrottlePolicy::RECOMMENDED.window_ms;
    }
}

#[test]
fn four_failures_and_a_success_start_over() {
    let mut t = throttle();
    let src = ip("203.0.113.7");
    fail(&mut t, src, Attempt::SignIn, 4, 0);
    t.record_success(USER, src);
    fail(&mut t, src, Attempt::SignIn, 4, 1);
    assert_eq!(t.admit(USER, src, Attempt::SignIn, 2), Decision::Admit);
}

#[test]
fn neighbours_share_a_network_key_and_other_accounts_do_not() {
    let mut t = throttle();
    fail(&mut t, ip("203.0.113.7"), Attempt::SignIn, 5, 0);
    assert_eq!(
        t.admit(USER, ip("203.0.113.200"), Attempt::SignIn, 1),
        Decision::Refuse
    );
    assert_eq!(
        t.admit(USER, ip("198.51.100.7"), Attempt::SignIn, 1),
        Decision::Admit
    );
    assert_eq!(
        t.admit("bob", ip("203.0.113.7"), Attempt::SignIn, 1),
        Decision::Admit
    );
    fail(&mut t, ip("2001:db8:1:2::1"), Attempt::SignIn, 5, 2);
    assert_eq!(
        t.admit(USER, ip("2001:db8:1:2:ffff::9"), Attempt::SignIn, 3),
        Decision::Refuse
    );
}

/// Control: drop the username-only key from `keys` and this goes red.
#[test]
fn guesses_spread_over_many_networks_still_lock_the_account() {
    let mut t = throttle();
    for n in 0..15u32 {
        let src = ip(&format!("10.{n}.0.1"));
        assert_eq!(
            t.admit(USER, src, Attempt::SignIn, 0),
            Decision::Admit,
            "{n}"
        );
        t.record_failure(USER, src, Attempt::SignIn, 0);
    }
    assert_eq!(
        t.admit(USER, ip("10.99.0.1"), Attempt::SignIn, 1),
        Decision::Refuse
    );
}

#[test]
fn a_recovery_attempt_counts_twice() {
    let mut t = throttle();
    let src = ip("203.0.113.7");
    fail(&mut t, src, Attempt::Recovery, 3, 0);
    assert_eq!(t.admit(USER, src, Attempt::Recovery, 1), Decision::Refuse);
    assert_eq!(t.admit(USER, src, Attempt::SignIn, 1), Decision::Refuse);

    let mut t = throttle();
    for _ in 0..10 {
        assert_eq!(t.admit(USER, src, Attempt::Recovery, 0), Decision::Admit);
    }
    assert_eq!(t.admit(USER, src, Attempt::Recovery, 0), Decision::Refuse);
}

#[test]
fn twenty_starts_fill_a_window_and_the_next_window_is_open() {
    let mut t = throttle();
    let src = ip("203.0.113.7");
    for _ in 0..20 {
        assert_eq!(t.admit(USER, src, Attempt::SignIn, 0), Decision::Admit);
    }
    assert_eq!(t.admit(USER, src, Attempt::SignIn, 0), Decision::Refuse);
    let next = ThrottlePolicy::RECOMMENDED.window_ms;
    assert_eq!(t.admit(USER, src, Attempt::SignIn, next), Decision::Admit);
}

#[test]
fn a_full_table_forgets_idle_keys_then_the_oldest_unlocked_but_never_a_locked_one() {
    let policy = ThrottlePolicy {
        max_tracked_keys: 4,
        ..ThrottlePolicy::RECOMMENDED
    };
    let mut t = SignInThrottle::new(policy).unwrap();
    let src = ip("203.0.113.7");
    fail(&mut t, src, Attempt::SignIn, 5, 0);
    assert_eq!(t.tracked(), 2);
    assert_eq!(t.admit("bob", src, Attempt::SignIn, 1), Decision::Admit);
    assert_eq!(t.tracked(), 4);
    assert_eq!(t.admit("carol", src, Attempt::SignIn, 2), Decision::Admit);
    assert_eq!(t.tracked(), 4);
    assert_eq!(
        t.admit(USER, src, Attempt::SignIn, 3),
        Decision::Refuse,
        "the lockout was forgotten"
    );
}

#[test]
fn a_policy_that_would_admit_or_lock_nothing_is_refused() {
    let base = ThrottlePolicy::RECOMMENDED;
    for bad in [
        ThrottlePolicy {
            max_failures: 0,
            ..base
        },
        ThrottlePolicy {
            max_starts_per_window: 0,
            ..base
        },
        ThrottlePolicy {
            window_ms: 0,
            ..base
        },
        ThrottlePolicy {
            lockout_base_ms: 0,
            ..base
        },
        ThrottlePolicy {
            lockout_max_ms: base.lockout_base_ms - 1,
            ..base
        },
        ThrottlePolicy {
            max_tracked_keys: 1,
            ..base
        },
    ] {
        assert!(SignInThrottle::new(bad).is_err(), "{bad:?}");
    }
}
