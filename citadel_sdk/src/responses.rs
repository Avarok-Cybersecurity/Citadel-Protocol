//! A list of helpers making the response phase simple and intuitive
//!
//! Generally, when making a response, the response must be sent outbound through
//! the [NodeRemote](crate::prelude::NodeRemote) with a custom ticket equivalent to the ticket receieved by
//! the external request in order for the peer to listen for a response. Additionally,
//! [PeerConnectionType](crate::prelude::PeerConnectionType) data must be `.reverse()`'d. Finally, some response types
//! require the manual input of usernames, and as such, this helper library enforces
//! all these requirements
use crate::prelude::*;

/// Given the `input_signal` from the peer, this function sends a register response to the target peer
pub async fn peer_register(
    input_signal: PeerSignal,
    accept: bool,
    remote: &impl Remote,
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
                    implicated_cid: this_cid,
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
pub async fn peer_connect(
    input_signal: PeerSignal,
    accept: bool,
    remote: &impl Remote,
) -> Result<Ticket, NetworkError> {
    if let PeerSignal::PostConnect {
        peer_conn_type: v_conn,
        ticket_opt: ticket,
        invitee_response: None,
        session_security_settings: sess_sec,
        udp_mode,
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
            implicated_cid: this_cid,
            command: PeerSignal::PostConnect {
                peer_conn_type: v_conn.reverse(),
                ticket_opt: Some(ticket),
                invitee_response: Some(resp),
                session_security_settings: sess_sec,
                udp_mode,
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
pub async fn group_invite(
    invite_signal: NodeResult,
    accept: bool,
    remote: &impl Remote,
) -> Result<Ticket, NetworkError> {
    if let NodeResult::GroupEvent(GroupEvent {
        implicated_cid: cid,
        ticket,
        event: GroupBroadcast::Invitation { key },
    }) = invite_signal
    {
        let resp = if accept {
            GroupBroadcast::AcceptMembership { key }
        } else {
            GroupBroadcast::DeclineMembership { key }
        };

        let request = NodeRequest::GroupBroadcastCommand(GroupBroadcastCommand {
            implicated_cid: cid,
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
