//! Which channel a media session's fragments ride.

use crate::ids::SettingId;
use crate::setting::{ApplyPath, Setting};
use serde::{Deserialize, Serialize};

/// The same two transports as `citadel_sdk::media::MediaTransportKind`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MediaTransportKind {
    /// The session UDP channel (lossy, unordered).
    Unreliable,
    /// The ordered-reliable channel.
    Reliable,
}

/// Ordered by reliability: when either side asks for the reliable channel, both use it, so the
/// two ends can never pick different transports from their own timers.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MediaTransport {
    pub kind: MediaTransportKind,
}

fn rank(transport: &MediaTransport) -> u8 {
    match transport.kind {
        MediaTransportKind::Unreliable => 0,
        MediaTransportKind::Reliable => 1,
    }
}

impl Setting for MediaTransport {
    const ID: SettingId = SettingId::MEDIA_TRANSPORT;
    const PERSIST: bool = false;

    fn merge(leader: &Self, loser: &Self) -> Self {
        if rank(loser) > rank(leader) {
            *loser
        } else {
            *leader
        }
    }

    fn is_downgrade(from: &Self, to: &Self) -> Option<bool> {
        Some(rank(to) < rank(from))
    }

    fn path(_from: &Self, _to: &Self) -> ApplyPath {
        ApplyPath::InBandLocal
    }

    fn is_supported(&self) -> bool {
        true
    }

    /// Nothing about a transport is costly to build: there is no bound.
    type Bound = ();

    fn exceeds(&self, _bound: &()) -> bool {
        false
    }
}
