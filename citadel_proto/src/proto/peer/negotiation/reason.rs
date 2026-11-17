//! Why a P2P connection was closed on purpose.
//!
//! A deliberate drop and a lost link used to reach the peer identically, so the peer could only
//! redial. The reason travels two ways, because one of them does not survive every server:
//!
//! - in `PeerSignal::Disconnect.reason`, appended last. The server does not relay a peer's
//!   `Disconnect` as bytes: it decodes it and builds the signals it sends from the fields it
//!   knows. A server at [`NEGOTIATION_SINCE`](crate::constants::NEGOTIATION_SINCE) copies the
//!   reason across; an older one reads the signal without it and sends it on without it.
//! - on the connection's own negotiation lane, end to end, before the `Disconnect` is sent: the
//!   peer's SDK records it against the connection ([`PeerClosing`]) and acknowledges it, and
//!   only then does the closing side disconnect. Whatever the server rebuilt, the peer reports
//!   the `Disconnect` that follows with the reason it recorded.

use citadel_io::Mutex;
use citadel_negotiation::{RenegotiationReason, SettingId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Why a connection was closed on purpose. `None` in `PeerSignal::Disconnect.reason` means a
/// lost link, an application that gave no reason, or a peer or server that predates the field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DisconnectReason {
    /// A setting could not be changed on the live connection: the closing side redials at the
    /// agreed value. The peer should wait to be dialled rather than redial itself.
    Renegotiation {
        setting: SettingId,
        reason: RenegotiationReason,
    },
}

/// The reason the peer gave, over the lane, for closing one connection. Written by the lane's
/// receive task and read by every path that reports that connection's end.
#[derive(Clone, Default)]
pub struct PeerClosing {
    reason: Arc<Mutex<Option<DisconnectReason>>>,
}

impl std::fmt::Debug for PeerClosing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PeerClosing").field(&self.reason()).finish()
    }
}

impl PeerClosing {
    pub(crate) fn record(&self, reason: DisconnectReason) {
        *self.reason.lock() = Some(reason);
    }

    /// The reason the peer gave for closing this connection, if it gave one.
    pub fn reason(&self) -> Option<DisconnectReason> {
        *self.reason.lock()
    }
}

/// The reason to report for a connection's end: the one its `Disconnect` carried, or else the
/// one the peer gave on the lane (a server that rebuilt the signal without it).
pub(crate) fn reported_reason(
    carried: Option<DisconnectReason>,
    closing: Option<&PeerClosing>,
) -> Option<DisconnectReason> {
    carried.or_else(|| closing.and_then(PeerClosing::reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RENEGOTIATION: DisconnectReason = DisconnectReason::Renegotiation {
        setting: SettingId::KEY_PROFILE,
        reason: RenegotiationReason::PeerLegacy,
    };

    #[test]
    fn the_carried_reason_wins_and_the_lane_fills_a_missing_one() {
        let closing = PeerClosing::default();
        assert_eq!(reported_reason(None, Some(&closing)), None);
        closing.record(RENEGOTIATION);
        assert_eq!(reported_reason(None, Some(&closing)), Some(RENEGOTIATION));
        let other = DisconnectReason::Renegotiation {
            setting: SettingId::MEDIA_TRANSPORT,
            reason: RenegotiationReason::Desync,
        };
        assert_eq!(reported_reason(Some(other), Some(&closing)), Some(other));
        assert_eq!(reported_reason(None, None), None);
    }
}
