//! # N-Node Group Synchronization Primitives
//!
//! Fault-tolerant distributed lock primitives for `n >= 2` members connected by a
//! full mesh of [`crate::reliable_conn::ReliableOrderedStreamToTarget`] pipes.
//!
//! Unlike the 2-node primitives in [`crate::sync::primitives`], these tolerate
//! `f < n/2` member crashes and arbitrary network partitions while preserving
//! mutual exclusion of grant epochs (safety) — liveness requires a connected
//! majority of the configured membership.
//!
//! ## Algorithm
//! Each lock is a single replicated register (a [`record::LockRecord`]) maintained by a
//! CASPaxos-style consensus round: every lock operation is a pure compare-and-swap
//! ([`ops::apply`]) proposed via Prepare/Promise → Accept/Accepted against a majority
//! of the members. There is no leader and no election. Grants carry:
//! - a **lease** measured on each observer's local monotonic clock (never wall clocks),
//! - a monotonic **fencing token** ([`Fence`]) that external systems can verify,
//! - a **recovered** flag when the previous writer crashed mid-critical-section.
//!
//! Crashed holders are removed by a *steal* CAS gated on a frozen `(fence, lease_seq)`
//! snapshot observed unchanged for `lease_duration + steal_grace` on the stealer's own
//! clock. A steal never grants the lock to anyone: the next holder must run its own
//! claim round, which structurally eliminates stale-grant races.
//!
//! ## Modules
//! Pure (no I/O, no clocks — deterministic unit tests): [`record`], [`ops`],
//! [`admission`], [`acceptor`], [`lease`], [`wire`], [`config`], [`error`].
//! Async drivers: [`transport`], [`proposer`], [`engine`], [`guard`],
//! [`mutex`], [`rwlock`].

use serde::{Deserialize, Serialize};

pub mod acceptor;
pub(crate) mod acquire;
pub(crate) mod acquire_wait;
pub mod admission;
pub mod config;
pub(crate) mod create;
pub mod engine;
pub(crate) mod engine_util;
pub mod error;
pub(crate) mod grant_state;
pub mod guard;
pub mod lease;
pub mod mutex;
pub mod op_types;
pub mod ops;
pub(crate) mod ops_grant;
pub mod persist;
pub mod proposer;
pub(crate) mod proposer_read;
pub mod record;
pub mod rwlock;
#[cfg(not(target_family = "wasm"))]
pub mod test_mesh;
pub mod transport;
pub mod wire;

pub use config::GroupLockConfig;
pub use error::GroupLockError;
pub use guard::{NetGroupReadGuard, NetGroupWriteGuard};
pub use mutex::{NetGroupMutex, NetGroupMutexGuard};
pub use persist::{peek_value, SnapshotAcceptorStore};
pub use rwlock::NetGroupRwLock;
pub use transport::GroupTransport;

/// Stable, unique identity of a member within a lock group. The total order over
/// member ids doubles as the ballot tiebreak, so ids must be unique across the group.
#[derive(
    Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default,
)]
pub struct MemberId(pub u64);

/// Caller-assigned identity of a lock instance; must be identical on every member.
#[derive(
    Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default,
)]
pub struct LockId(pub u64);

impl LockId {
    /// Derives a `LockId` from a human-readable name via FNV-1a, so all members can
    /// agree on an id without coordinating (`LockId::from_name("session-counter")`).
    pub fn from_name(name: &str) -> Self {
        Self(fnv1a(name.as_bytes()))
    }
}

/// Monotonic fencing token. A new fence is minted for every grant (read or write),
/// strictly increasing across the lock's linearized history. Pass it to external
/// systems so they can reject operations from stale (paused/partitioned) holders.
#[derive(
    Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default,
)]
pub struct Fence(pub u64);

/// The mode a lock is held or requested in.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum LockKind {
    Read,
    Write,
}

pub(crate) fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod ops_tests;

#[cfg(test)]
#[path = "ops_tests_fault.rs"]
mod ops_tests_fault;

#[cfg(test)]
#[path = "ops_tests_replay.rs"]
mod ops_tests_replay;

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "test_util.rs"]
mod test_util;

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "integration_tests.rs"]
mod integration_tests;

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "fault_tests.rs"]
mod fault_tests;

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "persist_tests.rs"]
mod persist_tests;

#[cfg(test)]
#[path = "sim_tests.rs"]
mod sim_tests;

#[cfg(test)]
#[path = "adversary_tests.rs"]
mod adversary_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_id_from_name_is_stable_and_distinct() {
        assert_eq!(LockId::from_name("a"), LockId::from_name("a"));
        assert_ne!(LockId::from_name("a"), LockId::from_name("b"));
    }
}
