//! The order a server gives a group's broadcasts, and the log a group may ask it to keep.
//!
//! Every broadcast a server fans out to a group (a message, a Commit) takes the group's next
//! sequence number, one order across all senders. A group with *replay* ([`GroupLogLimits`],
//! asked for at creation or turned on later by its owner) also has its broadcasts kept, in that
//! order, in one log: from the position replay started at, the numbers have no gaps, a member
//! that was away is replayed from the last number it holds, a gap is fetched, and its membership
//! and ownership changes take a number too. A group without replay is numbered, but its numbers
//! may skip after a server restart and nothing is fetched.

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::time::Duration;
#[cfg(feature = "typescript")]
use ts_rs::TS;

/// The smallest application body every replay group carries: a log that admits a body this size
/// sealed (the group's end-to-end encryption and its sender's signature) is required of every
/// replay group, so a consumer can count on it.
pub const MIN_REPLAY_BODY_BYTES: u32 = 16_384;

/// The most sealing adds to a body: the sender's ML-DSA-65 signature (3 309 bytes), the frame
/// header, the AEAD tag and the encoding. A replay group's `max_message_bytes` must be at least
/// [`MIN_REPLAY_BODY_BYTES`] plus this.
pub const MAX_SEALING_OVERHEAD_BYTES: u32 = 8_192;

/// A client-chosen id for one message. A message sent again with the same id (a retry after a
/// lost answer) is given the position the first one got, and is not relayed twice.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GroupMessageId(#[cfg_attr(feature = "typescript", ts(type = "number[]"))] pub [u8; 16]);

impl GroupMessageId {
    /// A fresh random id.
    pub fn random() -> Self {
        Self(uuid::Uuid::new_v4().into_bytes())
    }
}

/// Where one broadcast stands in its group's order.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GroupPosition {
    /// The group's sequence number for it, from 1.
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
    pub seq: u64,
    /// In a replay group, the head of the group's log chain at this position:
    /// `SHA3-256("citadel-group-log-v1" ‖ group ‖ seq ‖ previous head ‖ SHA3-256(frame))`. Two
    /// members holding the same head at the same `seq` were shown the same history up to it.
    /// `None` outside replay.
    #[cfg_attr(feature = "typescript", ts(type = "number[] | null"))]
    pub chain: Option<[u8; 32]>,
}

/// How much of a replay group's log its server keeps, and the largest message it relays to it.
/// A group asks for these; its server holds it to no more than its own maximum
/// (`NodeBuilder::with_group_log_limits`), and refuses a group whose limits cannot carry
/// [`MIN_REPLAY_BODY_BYTES`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GroupLogLimits {
    /// The longest an entry is kept.
    #[cfg_attr(feature = "typescript", ts(type = "{ secs: bigint, nanos: number }"))]
    pub max_age: Duration,
    /// The most entries kept.
    pub max_messages: u32,
    /// The most bytes kept.
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
    pub max_bytes: u64,
    /// The largest message (relayed ciphertext) the group takes.
    pub max_message_bytes: u32,
}

/// Why a group's log limits were refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum GroupReplayRefusal {
    /// The limits cannot carry a sealed body of [`MIN_REPLAY_BODY_BYTES`].
    TooSmall,
    /// This server keeps no group logs (it was built without `with_group_log_limits`).
    NotKept,
    /// Only the group's owner turns replay on.
    NotTheOwner,
    /// The group already has replay, or does not exist here, or is ephemeral.
    NotApplicable,
}

impl Display for GroupReplayRefusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall => write!(
                f,
                "the group's log limits cannot carry a {MIN_REPLAY_BODY_BYTES}-byte body"
            ),
            Self::NotKept => write!(f, "this server keeps no group logs"),
            Self::NotTheOwner => write!(f, "only the group's owner turns replay on"),
            Self::NotApplicable => write!(f, "replay cannot be turned on for this group"),
        }
    }
}

impl GroupLogLimits {
    /// The smallest `max_message_bytes` a replay group may have.
    pub const MIN_MESSAGE_BYTES: u32 = MIN_REPLAY_BODY_BYTES + MAX_SEALING_OVERHEAD_BYTES;

    /// Whether these limits can carry the body every replay group must.
    pub fn validate(&self) -> Result<(), GroupReplayRefusal> {
        let carries = self.max_message_bytes >= Self::MIN_MESSAGE_BYTES
            && self.max_bytes >= u64::from(self.max_message_bytes)
            && self.max_messages >= 1
            && !self.max_age.is_zero();
        carries.then_some(()).ok_or(GroupReplayRefusal::TooSmall)
    }

    /// These limits, held to no more than `server`'s.
    pub fn clamped_to(&self, server: &Self) -> Self {
        Self {
            max_age: self.max_age.min(server.max_age),
            max_messages: self.max_messages.min(server.max_messages),
            max_bytes: self.max_bytes.min(server.max_bytes),
            max_message_bytes: self.max_message_bytes.min(server.max_message_bytes),
        }
    }
}

/// What a member of a replay group is told of its order: when replay started, where the log's
/// head was, where it joined, and the limits that apply.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GroupOrderInfo {
    /// The first position of the log: numbering has no gaps from here on.
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
    pub since: u64,
    /// The last position the server had given when it told the member this.
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
    pub head: u64,
    /// The first position this member can read, when it joined after replay started (its
    /// Welcome); positions before it come to it from another member, not from the group.
    #[cfg_attr(feature = "typescript", ts(type = "bigint | null"))]
    pub joined: Option<u64>,
    /// The limits the server applies to the log, already held to its maximum.
    pub limits: GroupLogLimits,
}

/// Why a replay group's channel stopped delivering in order. Nothing past `last` is delivered
/// until the member resumes the group again.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum GroupOrderBroken {
    /// The positions after `last` are older than the log keeps; the log starts at `earliest`.
    Trimmed {
        #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
        earliest: u64,
    },
    /// More broadcasts arrived past a gap than this member holds while it fetches the gap.
    BufferFull,
}

#[cfg(test)]
#[path = "group_order_tests.rs"]
mod tests;
