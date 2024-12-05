//! Post-Registration Handler for Server-Side Peer Operations
//!
//! This module handles the post-registration phase of peer-to-peer communication on
//! the server side. It manages peer registration responses, HyperLAN P2P setup,
//! and registration state management between peers.
//!
//! # Features
//!
//! - Peer registration response handling
//! - HyperLAN P2P registration
//! - Username validation
//! - Signal routing
//! - Ticket management
//! - Response processing
//!
//! # Important Notes
//!
//! - Server-side operations only
//! - Handles registration declines
//! - Asynchronous registration
//! - TODO: Implement error routing
//!
//! # Related Components
//!
//! - `CitadelSession`: Session management
//! - `AccountManager`: Registration handling
//! - `PeerSignal`: Signal processing
//! - `PeerResponse`: Response types
//! - `SecurityLevel`: Security settings

use crate::error::NetworkError;
use crate::prelude::{PeerConnectionType, PeerResponse, PeerSignal};
use crate::proto::packet_processor::peer::peer_cmd_packet::route_signal_response;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::peer::peer_layer::Username;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use citadel_crypt::stacked_ratchet::Ratchet;
use citadel_types::crypto::SecurityLevel;

#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = session.is_server, session_cid = session_cid, target_cid = target_cid)
))]
#[allow(clippy::too_many_arguments)]
pub async fn handle_response_phase_post_register<R: Ratchet>(
    peer_conn_type: PeerConnectionType,
    username: Username,
    peer_response: PeerResponse,
    ticket: Ticket,
    session_cid: u64,
    target_cid: u64,
    timestamp: i64,
    session: &CitadelSession<R>,
    sess_stacked_ratchet: &R,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let decline = matches!(&peer_response, PeerResponse::Decline);

    route_signal_response(PeerSignal::PostRegister {
        peer_conn_type,
        inviter_username: username,
        invitee_username: None,
        ticket_opt: Some(ticket),
        invitee_response: Some(peer_response),
    }, session_cid, target_cid, timestamp, ticket, session.clone(), sess_stacked_ratchet,
                          |this_sess, _peer_sess, _original_tracked_posting| {
                              if !decline {
                                  let account_manager = this_sess.account_manager.clone();
                                  let task = async move {
                                      if let Err(err) = account_manager.register_hyperlan_p2p_as_server(session_cid, target_cid).await {
                                          // TODO: route error
                                          log::error!(target: "citadel", "Unable to register hyperlan p2p at server: {:?}", err);
                                      }
                                  };

                                  let handle = citadel_io::tokio::task::spawn(task);
                                  // dont process the handle
                                  std::mem::drop(handle);
                              }
                          }, security_level).await
}
