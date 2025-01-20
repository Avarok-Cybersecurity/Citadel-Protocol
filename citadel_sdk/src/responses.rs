//! Protocol Response Helpers
//!
//! This module provides helper functions for handling responses to various protocol
//! operations in the Citadel Protocol. It simplifies the process of sending responses
//! to peer registration, connection, and group invitation requests.
//!
//! # Features
//! - Peer registration response handling
//! - Peer connection response management
//! - Group invitation response processing
//! - Automatic ticket management
//! - Connection type reversal handling
//! - Username resolution and validation
//!
//! # Example
//! ```rust
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::responses;
//!
//! async fn handle_peer_request<R: Ratchet>(
//!     signal: PeerSignal,
//!     remote: &impl Remote<R>
//! ) -> Result<(), NetworkError> {
//!     // Accept a peer registration request
//!     let ticket = responses::peer_register(signal, true, remote).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//! - Responses must match request tickets
//! - Connection types are automatically reversed
//! - Username resolution is handled internally
//! - Group responses require server connection
//!
//! # Related Components
//! - [`Remote`]: Network communication interface
//! - [`PeerSignal`]: Peer communication events
//! - [`NodeResult`]: Network operation results
//! - [`Ticket`]: Request/response correlation
//!
//! [`Remote`]: crate::prelude::Remote
//! [`PeerSignal`]: crate::prelude::PeerSignal
//! [`NodeResult`]: crate::prelude::NodeResult
//! [`Ticket`]: crate::prelude::Ticket

use crate::prelude::*;

/// Given the `input_signal` from the peer, this function sends a register response to the target peer
pub async fn peer_register<R: Ratchet>(
    input_signal: PeerSignal,
    accept: bool,
    remote: &impl Remote<R>,
) -> Result<Ticket, NetworkError> {
    if let PeerSignal::PostRegister {
        peer_conn_type: v_conn,
        inviter_username: username,
        invitee_username: username_opt,
        ticket_opt: ticket,
        invitee_response: None,
    } = input_signal
    {
        let this_cid = v_conn.get_original_target_cid();
        let ticket = get_ticket(ticket)?;
        let resp = if accept {
            let username = remote
                .account_manager()
                .get_username_by_cid(this_cid)
                .await
                .map_err(|err| NetworkError::Generic(err.into_string()))?
                .ok_or(NetworkError::InvalidRequest(
                    "Unable to find local username implied by signal",
                ))?;
            PeerResponse::Accept(Some(username))
        } else {
            PeerResponse::Decline
        };

        // v_conn must be reversed when rebounding a signal
        let signal = PeerSignal::PostRegister {
            peer_conn_type: v_conn.reverse(),
            inviter_username: username,
            invitee_username: username_opt,
            ticket_opt: Some(ticket),
            invitee_response: Some(resp),
        };
        remote
            .send_with_custom_ticket(
                ticket,
                NodeRequest::PeerCommand(PeerCommand {
                    session_cid: this_cid,
                    command: signal,
                }),
            )
            .await
            .map(|_| ticket)
    } else {
        Err(NetworkError::InternalError(
            "Input signal is not a valid PostRegister",
        ))
    }
}

/// Given the `input_signal` from the peer, this function sends a connect response to the target peer
pub async fn peer_connect<R: Ratchet>(
    input_signal: PeerSignal,
    accept: bool,
    remote: &impl Remote<R>,
    peer_session_password: Option<PreSharedKey>,
) -> Result<Ticket, NetworkError> {
    if let PeerSignal::PostConnect {
        peer_conn_type: v_conn,
        ticket_opt: ticket,
        invitee_response: None,
        session_security_settings: sess_sec,
        udp_mode,
        session_password: None,
    } = input_signal
    {
        let this_cid = v_conn.get_original_target_cid();
        let ticket = get_ticket(ticket)?;
        let resp = if accept {
            // we do not need a username here, unlike in postregister
            PeerResponse::Accept(None)
        } else {
            PeerResponse::Decline
        };

        let signal = NodeRequest::PeerCommand(PeerCommand {
            session_cid: this_cid,
            command: PeerSignal::PostConnect {
                peer_conn_type: v_conn.reverse(),
                ticket_opt: Some(ticket),
                invitee_response: Some(resp),
                session_security_settings: sess_sec,
                udp_mode,
                session_password: peer_session_password,
            },
        });
        remote
            .send_with_custom_ticket(ticket, signal)
            .await
            .map(|_| ticket)
    } else {
        Err(NetworkError::InternalError(
            "Input signal is not a valid PostConnect",
        ))
    }
}

/// Given a group invite signal, this function sends a response to the server
pub async fn group_invite<R: Ratchet>(
    invite_signal: NodeResult<R>,
    accept: bool,
    remote: &impl Remote<R>,
) -> Result<Ticket, NetworkError> {
    if let NodeResult::GroupEvent(GroupEvent {
        session_cid: cid,
        ticket,
        event: GroupBroadcast::Invitation { sender: _, key },
    }) = invite_signal
    {
        let resp = if accept {
            GroupBroadcast::AcceptMembership { target: cid, key }
        } else {
            GroupBroadcast::DeclineMembership { target: cid, key }
        };

        let request = NodeRequest::GroupBroadcastCommand(GroupBroadcastCommand {
            session_cid: cid,
            command: resp,
        });
        remote
            .send_with_custom_ticket(ticket, request)
            .await
            .map(|_| ticket)
    } else {
        Err(NetworkError::InternalError(
            "Input signal is not a group invitation",
        ))
    }
}

fn get_ticket(ticket: Option<Ticket>) -> Result<Ticket, NetworkError> {
    ticket.ok_or(NetworkError::InvalidPacket(
        "This event was improperly formed",
    ))
}
