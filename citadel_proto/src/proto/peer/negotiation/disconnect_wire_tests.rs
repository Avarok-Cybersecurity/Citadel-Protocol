//! `PeerSignal::Disconnect.reason` on the wire: appended last, so an older node reads around it.

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

/// An older node reads a signal as its own fields followed by bytes it ignores: the new encoding
/// must be the old one with the reason appended (the old one is the new one without the single
/// byte of an absent reason).
#[test]
fn a_disconnect_is_the_old_encoding_with_the_reason_appended() {
    let without = disconnect(None).serialize_to_vector().unwrap();
    let legacy = &without[..without.len() - 1];
    let with = disconnect(Some(REASON)).serialize_to_vector().unwrap();
    assert!(with.starts_with(legacy));
    let read = PeerSignal::deserialize_from_vector(&with).unwrap();
    assert_eq!(reason_of(read), Some(REASON));
}

#[test]
fn a_disconnect_from_an_older_node_reads_as_no_reason() {
    let without = disconnect(None).serialize_to_vector().unwrap();
    let legacy = &without[..without.len() - 1];
    let read = PeerSignal::deserialize_from_vector(legacy)
        .expect("a Disconnect from an older node must still parse");
    assert_eq!(reason_of(read), None);
}
