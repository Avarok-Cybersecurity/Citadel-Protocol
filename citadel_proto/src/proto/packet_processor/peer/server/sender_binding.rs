//! A server acts only on the CID it authenticated.
//!
//! A signal names its sender in its body: the `session_cid` of its connection type, or a
//! `session_cid` field. A client always names itself there (a response reverses the request's
//! connection type, so its sender comes first too). The server reads the sender from the session
//! the signal arrived on and writes it into every one of those fields before it acts, so each
//! registration, deregistration, connection, key exchange and group lookup it performs, and every
//! signal it relays, is the authenticated session's own.

use crate::proto::peer::peer_layer::PeerSignal;
use citadel_types::proto::{ClientConnectionType, PeerConnectionType};

/// `signal`, with every sender field set to the authenticated `sender`.
pub(crate) fn as_sent_by(mut signal: PeerSignal, sender: u64) -> PeerSignal {
    match &mut signal {
        PeerSignal::PostRegister { peer_conn_type, .. }
        | PeerSignal::Deregister { peer_conn_type }
        | PeerSignal::PostConnect { peer_conn_type, .. }
        | PeerSignal::Disconnect { peer_conn_type, .. }
        | PeerSignal::DisconnectUDP { peer_conn_type, .. }
        | PeerSignal::PostFileUploadRequest { peer_conn_type, .. }
        | PeerSignal::AcceptFileUploadRequest { peer_conn_type, .. }
        | PeerSignal::DeregistrationSuccess { peer_conn_type }
        | PeerSignal::Kex { peer_conn_type, .. }
        | PeerSignal::WebRtcSignaling { peer_conn_type, .. }
        | PeerSignal::SignalError {
            peer_connection_type: peer_conn_type,
            ..
        } => set_peer_sender(peer_conn_type, sender),
        PeerSignal::GetRegisteredPeers { peer_conn_type, .. }
        | PeerSignal::GetMutuals {
            v_conn_type: peer_conn_type,
            ..
        } => set_client_sender(peer_conn_type, sender),
        PeerSignal::BroadcastConnected { session_cid, .. }
        | PeerSignal::SignInManagement { session_cid, .. } => *session_cid = sender,
        PeerSignal::SignalReceived { .. } => {}
    }
    signal
}

fn set_peer_sender(conn: &mut PeerConnectionType, sender: u64) {
    match conn {
        PeerConnectionType::LocalGroupPeer { session_cid, .. }
        | PeerConnectionType::ExternalGroupPeer { session_cid, .. } => *session_cid = sender,
    }
}

fn set_client_sender(conn: &mut ClientConnectionType, sender: u64) {
    match conn {
        ClientConnectionType::Server { session_cid }
        | ClientConnectionType::Extended { session_cid, .. } => *session_cid = sender,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::peer::peer_crypt::KeyExchangeProcess;
    use citadel_types::proto::UdpMode;

    const SESSION: u64 = 10;
    const NAMED: u64 = 77;
    const PEER: u64 = 20;

    fn naming(sender: u64) -> PeerConnectionType {
        PeerConnectionType::LocalGroupPeer {
            session_cid: sender,
            peer_cid: PEER,
        }
    }

    fn bound_conn(signal: PeerSignal) -> PeerConnectionType {
        match as_sent_by(signal, SESSION) {
            PeerSignal::Deregister { peer_conn_type }
            | PeerSignal::PostConnect { peer_conn_type, .. }
            | PeerSignal::Disconnect { peer_conn_type, .. }
            | PeerSignal::Kex { peer_conn_type, .. } => peer_conn_type,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn every_server_handled_peer_signal_names_the_authenticated_sender() {
        let signals = [
            PeerSignal::Deregister {
                peer_conn_type: naming(NAMED),
            },
            PeerSignal::PostConnect {
                peer_conn_type: naming(NAMED),
                ticket_opt: None,
                invitee_response: None,
                session_security_settings: crate::prelude::SessionSecuritySettingsBuilder::default(
                )
                .build()
                .unwrap(),
                udp_mode: UdpMode::Disabled,
                session_password: None,
            },
            PeerSignal::Disconnect {
                peer_conn_type: naming(NAMED),
                disconnect_response: None,
                disconnect_token: None,
                reason: None,
            },
            PeerSignal::Kex {
                peer_conn_type: naming(NAMED),
                kex_payload: KeyExchangeProcess::HolePunchFailed,
                sender_protocol_version: None,
                path: None,
                auth: None,
            },
        ];
        for signal in signals {
            assert_eq!(bound_conn(signal), naming(SESSION));
        }
    }

    #[test]
    fn the_peer_a_signal_is_for_is_kept() {
        let conn = bound_conn(PeerSignal::Deregister {
            peer_conn_type: naming(NAMED),
        });
        assert_eq!(conn.get_original_target_cid(), PEER);
    }

    #[test]
    fn a_list_request_reads_the_authenticated_senders_list() {
        let signal = as_sent_by(
            PeerSignal::GetMutuals {
                v_conn_type: ClientConnectionType::Server { session_cid: NAMED },
                response: None,
            },
            SESSION,
        );
        let PeerSignal::GetMutuals { v_conn_type, .. } = signal else {
            panic!("unexpected {signal:?}");
        };
        assert_eq!(v_conn_type.session_cid(), SESSION);
    }

    #[test]
    fn an_honest_signal_is_unchanged() {
        assert_eq!(
            bound_conn(PeerSignal::Deregister {
                peer_conn_type: naming(SESSION),
            }),
            naming(SESSION)
        );
    }
}
