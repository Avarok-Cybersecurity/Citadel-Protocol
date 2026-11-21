//! `PeerSignal::Disconnect.reason` on the wire: a required field, so an encoding without it is refused.

use super::reason::DisconnectReason;
use crate::proto::disconnect_tracker::DisconnectToken;
use crate::proto::peer::peer_layer::{PeerConnectionType, PeerResponse, PeerSignal};
use crate::proto::remote::Ticket;
use citadel_negotiation::{RenegotiationReason, SettingId};
use citadel_user::serialization::SyncIO;

const REASON: DisconnectReason = DisconnectReason::Renegotiation {
    setting: SettingId::KEY_PROFILE,
    reason: RenegotiationReason::PeerLegacy,
};

fn disconnect(reason: Option<DisconnectReason>) -> PeerSignal {
    PeerSignal::Disconnect {
        peer_conn_type: PeerConnectionType::LocalGroupPeer {
            session_cid: 11,
            peer_cid: 22,
        },
        disconnect_response: Some(PeerResponse::Disconnected("bye".into())),
        disconnect_token: Some(DisconnectToken {
            cid: 11,
            connection_id: Ticket(7),
        }),
        reason,
    }
}

fn reason_of(signal: PeerSignal) -> Option<DisconnectReason> {
    match signal {
        PeerSignal::Disconnect { reason, .. } => reason,
        other => panic!("not a Disconnect: {other:?}"),
    }
}

#[test]
fn a_disconnect_carries_its_reason() {
    for reason in [None, Some(REASON)] {
        let bytes = disconnect(reason).serialize_to_vector().unwrap();
        let read = PeerSignal::deserialize_from_vector(&bytes).unwrap();
        assert_eq!(reason_of(read), reason);
    }
}

/// The encoding before the reason (the same bytes without its one-byte absent marker) does not
/// parse. `a_disconnect_carries_its_reason` is the control.
#[test]
fn a_disconnect_encoded_without_its_reason_is_refused() {
    let without = disconnect(None).serialize_to_vector().unwrap();
    let older = &without[..without.len() - 1];
    assert!(PeerSignal::deserialize_from_vector(older).is_err());
}
