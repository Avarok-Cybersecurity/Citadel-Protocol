//! The limits an example server uses. A server requires them: the SDK has no default.
//!
//! Sized for one modest machine. Clients behind one NAT share an address, so the per-address
//! limit leaves room for an office's concurrent sign-ins. The example clients register the legacy
//! way (these servers configure no post-quantum sign-in), so legacy registration is taken, with
//! four Argon2id hashes at once: at the default 64 MiB each, 256 MiB of hashing at most. Each
//! stream may queue what a client uses (256 MiB), and all of them together 1 GiB.

use citadel_sdk::prelude::{GroupMailLimits, LegacyRegistration, ServerLimits};
use std::num::NonZeroUsize;

pub fn one_machine() -> ServerLimits {
    let nonzero = |n: usize| NonZeroUsize::new(n).expect("a positive limit");
    ServerLimits {
        provisional_per_ip: nonzero(32),
        provisional_total: nonzero(1024),
        legacy_registration: LegacyRegistration::Accepted {
            concurrent_hashes: nonzero(4),
        },
        outbound_queued_per_stream: nonzero(256 * 1024 * 1024),
        outbound_queued_total: nonzero(1024 * 1024 * 1024),
        group_mail: GroupMailLimits {
            max_age: std::time::Duration::from_secs(7 * 24 * 3600),
            max_messages: nonzero(1_000),
            max_bytes: nonzero(16 * 1024 * 1024),
        },
    }
}
