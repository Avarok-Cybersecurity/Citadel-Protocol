//! Operation, outcome, and denial types for the pure CAS transition function
//! [`crate::sync::group::ops::apply`].

use crate::sync::group::record::PoisonInfo;
use crate::sync::group::{Fence, LockKind, MemberId};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum Op {
    /// Bootstrap by `initial_value_owner`: creates the record with the initial value.
    Init { value: Vec<u8> },
    /// Grant immediately if the write-preferring FIFO rule allows, else append a
    /// wait entry (unless `no_enqueue`, the `try_*` path).
    AcquireOrEnqueue {
        member: MemberId,
        nonce: u64,
        kind: LockKind,
        no_enqueue: bool,
    },
    /// Promote own queue entry to a grant; the requester proving its liveness by
    /// running this round IS the grant-time revalidation (a dead entry never claims).
    ClaimQueued { member: MemberId, nonce: u64 },
    /// Waiter heartbeat: bump own entry's `refresh_seq`.
    RefreshWait { member: MemberId, nonce: u64 },
    /// Holder heartbeat: bump own `lease_seq`.
    Renew {
        member: MemberId,
        nonce: u64,
        expect_fence: Fence,
        expect_lease_seq: u64,
    },
    /// Remove own grant; `new_value` (serialized T) commits atomically when the
    /// critical section mutated the value.
    Release {
        member: MemberId,
        nonce: u64,
        expect_fence: Fence,
        new_value: Option<Vec<u8>>,
    },
    /// Atomically convert own write grant into a read grant (fresh fence), publishing
    /// `new_value` if mutated. No upgrade op exists: read→write upgrades deadlock.
    Downgrade {
        member: MemberId,
        nonce: u64,
        expect_fence: Fence,
        new_value: Option<Vec<u8>>,
    },
    /// Remove a stagnant holder observed frozen at `(expect_fence, expect_lease_seq)`
    /// for a full locally-timed lease window. Poisons the record iff the target held
    /// Write. Never grants: the beneficiary must run its own `ClaimQueued`.
    Steal {
        target: MemberId,
        target_nonce: u64,
        expect_fence: Fence,
        expect_lease_seq: u64,
    },
    /// Remove a stagnant waiter observed frozen at `expect_refresh_seq`.
    EvictWaiter {
        target: MemberId,
        target_nonce: u64,
        expect_refresh_seq: u64,
    },
    /// Cancel own pending request. If the request raced a grant (committed but never
    /// observed), the grant is revoked WITHOUT poison — the canceller provably never
    /// entered the critical section — and any poison it had consumed is restored.
    Dequeue { member: MemberId, nonce: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpOutcome {
    Initialized,
    Granted {
        fence: Fence,
        recovered: Option<PoisonInfo>,
    },
    Enqueued {
        position: usize,
    },
    Refreshed,
    Renewed {
        lease_seq: u64,
    },
    Released,
    Downgraded {
        fence: Fence,
    },
    Stolen,
    Evicted,
    Dequeued {
        was_granted: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpDenied {
    /// No committed record yet; only `Init` may apply.
    Uninitialized,
    /// `Init` against an existing record.
    AlreadyInitialized,
    /// `no_enqueue` acquire on a contended lock.
    WouldBlock,
    /// Claim attempted while the entry is not admissible (or missing).
    NotAdmissible,
    /// The `(member, nonce)` wait entry is gone (evicted or never enqueued).
    NotQueued,
    /// The `(member, nonce)` holder entry is gone or its fence/seq moved on —
    /// the grant was stolen (or this is a stale retry of an applied op).
    NotHolder,
    /// Steal/EvictWaiter snapshot mismatch: the target advanced (it is alive).
    SnapshotMismatch,
    /// Steal/EvictWaiter target already removed. Success-equivalent for the caller.
    TargetGone,
    /// A record counter would overflow (defensive; unreachable via honest peers).
    CounterExhausted,
}
