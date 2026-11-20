//! The explicit `LinkPolicy` the protocol's own tests run with: `LinkPolicy` has no defaults, so
//! one fixture serves the mode, reattach and manager tests alike.

use citadel_link::{Backoff, FlapPolicy, HealPolicy, LinkPolicy};
use std::time::Duration;

/// Every bound explicit (the type has no defaults); small values keep the clock readable.
pub(crate) fn policy() -> LinkPolicy {
    let s = Duration::from_secs;
    LinkPolicy {
        heal: HealPolicy {
            backoff: Backoff {
                first_wait: s(1),
                factor: 2,
                max_wait: s(30),
            },
            max_attempts: Some(6),
            give_up_after: None,
        },
        reattach_grace: s(300),
        flap: FlapPolicy {
            window: s(60),
            max_transitions: 3,
            hold: s(20),
        },
        direct_rendezvous_budget: s(5),
        rendezvous_deadline: s(10),
        seal_deadline: s(10),
        probe_interval: None,
        settings_deadline: s(10),
        loser_redial_wait: s(2),
        rearm: Backoff {
            first_wait: s(5),
            factor: 2,
            max_wait: s(300),
        },
    }
}
