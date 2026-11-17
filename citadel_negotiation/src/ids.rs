//! The identities and units every other module speaks in.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// A peer's client id. The negotiator compares two of them to pick the [`Role`].
pub type Cid = u64;

/// One P2P connection of a pair (the SDK's `DisconnectToken.connection_id` ticket).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConnectionId(pub u128);

/// A point in time, in milliseconds, as the shell's [`Clock`](crate::ports::Clock) reports it.
/// The core never reads a clock: every [`step`](crate::Negotiator::step) is handed one of these.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Millis(pub u64);

impl Millis {
    /// The instant `span` after this one, saturating at the end of time.
    pub fn after(self, span: Duration) -> Millis {
        let span = u64::try_from(span.as_millis()).unwrap_or(u64::MAX);
        Millis(self.0.saturating_add(span))
    }
}

/// The agreed generation of one setting on one connection. It starts at 0 when the channel opens
/// and advances by exactly one per agreed and applied proposal.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Epoch(pub u32);

impl Epoch {
    /// The epoch an agreed proposal moves to; `None` once the counter is exhausted.
    pub fn next(self) -> Option<Epoch> {
        self.0.checked_add(1).map(Epoch)
    }
}

/// Which negotiable setting a frame or a negotiator is about. Ids are never reused.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SettingId(pub u16);

impl SettingId {
    /// The P2P key profile: security level and crypto parameters.
    pub const KEY_PROFILE: SettingId = SettingId(1);
    /// Async (server-stored) versus direct P2P file transfer.
    pub const TRANSFER_MODE: SettingId = SettingId(2);
    /// The media transport: the session UDP channel or the reliable fallback.
    pub const MEDIA_TRANSPORT: SettingId = SettingId(3);
    /// Reserved: `citadel.session` app-session terms (BATCH-1116 H2).
    pub const APP_SESSION_TERMS: SettingId = SettingId(4);
    /// Reserved: the synchronized.work tier.
    pub const WORK_TIER: SettingId = SettingId(5);
}

/// Who executes an agreed change. One rule for every setting (owner decision D2): the lower CID
/// leads, the same rule as the SDK's crossed-dial tiebreak, so the dial path and the in-band path
/// never disagree about who acts. Only the Leader triggers a key-epoch ratchet round.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Leader,
    Loser,
}

impl Role {
    /// The local side's role toward `peer`. Two ends with the same CID have no order.
    pub fn for_pair(local: Cid, peer: Cid) -> Option<Role> {
        match local.cmp(&peer) {
            std::cmp::Ordering::Less => Some(Role::Leader),
            std::cmp::Ordering::Greater => Some(Role::Loser),
            std::cmp::Ordering::Equal => None,
        }
    }
}
