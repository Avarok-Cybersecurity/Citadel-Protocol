//! Error type for the n-node group lock primitives.

use crate::sync::group::{Fence, MemberId};

#[derive(Debug)]
pub enum GroupLockError {
    /// The acquire deadline elapsed before the lock could be granted.
    Timeout,
    /// A majority of the configured members could not be reached within the
    /// operation's deadline. The op may or may not have partially propagated;
    /// all ops are idempotent under retry via their (member, nonce) identity.
    QuorumUnavailable,
    /// The local grant was revoked: another member observed this holder as
    /// stagnant and stole the entry (or the lease expired locally first).
    Stolen {
        /// The fence of the grant that was lost.
        fence: Fence,
    },
    /// `try_lock`/`try_read`/`try_write` would have blocked.
    WouldBlock,
    /// The lock record has not been initialized by `initial_value_owner` yet.
    Uninitialized,
    /// A configuration precondition failed (bad durations, duplicate members,
    /// local/owner not in the member set, n < 2, ...).
    InvalidConfig(String),
    /// `create()` was called with `Some(initial)` on a non-owner member, or
    /// `None` on the owner.
    InitialValueOwnership {
        local: MemberId,
        owner: MemberId,
    },
    /// The engine for this lock was shut down (its `NetGroup*` handle dropped).
    Shutdown,
    Serialization(String),
    Io(String),
}

impl core::fmt::Display for GroupLockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Timeout => write!(f, "group lock acquire timed out"),
            Self::QuorumUnavailable => {
                write!(f, "a majority of group members is unreachable")
            }
            Self::Stolen { fence } => {
                write!(f, "grant with fence {} was revoked/stolen", fence.0)
            }
            Self::WouldBlock => write!(f, "lock is contended (try_* would block)"),
            Self::Uninitialized => write!(f, "lock record not initialized by owner yet"),
            Self::InvalidConfig(msg) => write!(f, "invalid group lock config: {msg}"),
            Self::InitialValueOwnership { local, owner } => write!(
                f,
                "initial value must be supplied by owner {owner:?} exactly (local: {local:?})"
            ),
            Self::Shutdown => write!(f, "group lock engine was shut down"),
            Self::Serialization(msg) => write!(f, "serialization failure: {msg}"),
            Self::Io(msg) => write!(f, "group transport i/o failure: {msg}"),
        }
    }
}

impl std::error::Error for GroupLockError {}

impl From<bincode::Error> for GroupLockError {
    fn from(err: bincode::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}
