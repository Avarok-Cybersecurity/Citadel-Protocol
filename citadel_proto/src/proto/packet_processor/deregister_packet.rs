//! Deregistration Packet Processor for Citadel Protocol
//!
//! This module handles the deregistration process for clients in the Citadel Protocol
//! network. It manages the secure removal of client accounts and cleanup of associated
//! resources from both the client and server sides.
//!
//! # Features
//!
//! - Secure client deregistration
//! - Resource cleanup
//! - Session state validation
//! - Ticket-based tracking
//! - Success/failure handling
//!
//! # Important Notes
//!
//! - Client must be connected to deregister
//! - Process is irreversible
//! - Handles both client and server-side cleanup
//! - Maintains security during account removal
//! - Requires valid session state
//!
//! # Related Components
//!
//! - `StateContainer`: Manages deregistration state
//! - `AccountManager`: Handles account removal
//! - `SessionManager`: Manages session cleanup
//! - `KernelInterface`: Reports deregistration results
//!
//! # Example Usage
//!
//! ```no_run
//! use citadel_proto::proto::packet_processor::deregister_packet;
//! use citadel_proto::proto::CitadelSession;
//! use citadel_proto::proto::packet::HdpPacket;
//!
//! async fn handle_deregister(session: &CitadelSession, packet: HdpPacket) {
//!     let header_entropy_bank_vers = 1;
//!     match deregister_packet::process_deregister(session, packet, header_entropy_bank_vers).await {
//!         Ok(result) => {
//!             // Handle successful deregistration
//!         }
//!         Err(err) => {
//!             // Handle deregistration error
//!         }
//!     }
//! }
//! ```

use super::includes::*;
use crate::error::NetworkError;
use crate::proto::node_result::DeRegistration;
use crate::proto::packet_processor::primary_group_packet::get_orientation_safe_ratchet;
use citadel_crypt::stacked_ratchet::Ratchet;

/// processes a deregister packet. The client must be connected to the HyperLAN Server in order to DeRegister
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = session_ref.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get()
    )
))]
pub async fn process_deregister<R: Ratchet>(
    session_ref: &CitadelSession<R>,
    packet: HdpPacket,
    header_entropy_bank_vers: u32,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session_ref.clone();

    if !session.state.is_connected() {
        log::error!(target: "citadel", "disconnect packet received, but session state is not connected. Must be connected to deregister. Dropping");
        return Ok(PrimaryProcessorResult::Void);
    }

    let task = async move {
        let session = &session;
        let hr = {
            let state_container = inner_state!(session.state_container);
            return_if_none!(
                get_orientation_safe_ratchet(header_entropy_bank_vers, &state_container, None),
                "Could not get proper HR [deregister]"
            )
        };

        let timestamp = session.time_tracker.get_global_time_ns();
        let (header, payload, _, _) = packet.decompose();
        let (header, _payload, stacked_ratchet) = return_if_none!(
            validation::aead::validate(hr, &header, payload),
            "Unable to validate dereg packet"
        );
        let header = &header;
        let session_cid = header.session_cid.get();
        let security_level = header.security_level.into();

        match header.cmd_aux {
            packet_flags::cmd::aux::do_deregister::STAGE0 => {
                log::trace!(target: "citadel", "STAGE 0 DEREGISTER PACKET RECV");
                deregister_client_from_self(
                    session_cid,
                    session,
                    &stacked_ratchet,
                    timestamp,
                    security_level,
                )
                .await
            }

            packet_flags::cmd::aux::do_deregister::SUCCESS => {
                log::trace!(target: "citadel", "STAGE SUCCESS DEREGISTER PACKET RECV");
                deregister_from_hyperlan_server_as_client(session_cid, session).await
            }

            packet_flags::cmd::aux::do_deregister::FAILURE => {
                log::trace!(target: "citadel", "STAGE FAILURE DEREGISTER PACKET RECV");
                let state_container = inner_state!(session.state_container);
                let ticket = state_container.deregister_state.current_ticket;
                // state_container.deregister_state.on_fail();
                std::mem::drop(state_container);
                let cid = return_if_none!(session.session_cid.get(), "implicated CID not loaded");
                session
                    .kernel_tx
                    .unbounded_send(NodeResult::DeRegistration(DeRegistration {
                        session_cid: cid,
                        ticket_opt: ticket,
                        success: false,
                    }))?;
                log::error!(target: "citadel", "Unable to locally purge account {}. Please report this to the HyperLAN Server admin", cid);
                Ok(PrimaryProcessorResult::EndSession(
                    "Deregistration failure. Closing connection anyways",
                ))
            }

            _ => {
                log::error!(target: "citadel", "Invalid auxiliary command");
                Ok(PrimaryProcessorResult::Void)
            }
        }
    };

    to_concurrent_processor!(task)
}

async fn deregister_client_from_self<R: Ratchet>(
    session_cid: u64,
    session_ref: &CitadelSession<R>,
    ratchet: &R,
    timestamp: i64,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session_ref;
    let (acc_mgr, ticket) = {
        let state_container = inner_state!(session.state_container);
        let ticket = state_container.deregister_state.current_ticket;

        let acc_manager = session.account_manager.clone();
        std::mem::drop(state_container);
        (acc_manager, ticket)
    };

    let (ret, success) = match acc_mgr.delete_client_by_cid(session_cid).await {
        Ok(_) => {
            log::trace!(target: "citadel", "Successfully purged account {} locally!", session_cid);
            let stage_success_packet = packet_crafter::do_deregister::craft_final(
                ratchet,
                true,
                timestamp,
                security_level,
            );
            // At the end of the deregistration phase, the session also ends
            (
                PrimaryProcessorResult::ReplyToSender(stage_success_packet),
                true,
            )
        }

        Err(err) => {
            log::error!(target: "citadel", "Unable to locally purge account {}. Please report this to the HyperLAN Server admin ({:?})", session_cid, err);
            let stage_failure_packet = packet_crafter::do_deregister::craft_final(
                ratchet,
                false,
                timestamp,
                security_level,
            );
            (
                PrimaryProcessorResult::ReplyToSender(stage_failure_packet),
                false,
            )
        }
    };

    let session = session_ref;

    session.send_to_kernel(NodeResult::DeRegistration(DeRegistration {
        session_cid,
        ticket_opt: ticket,
        success,
    }))?;

    // This ensures no further packets are processed
    session.state.set(SessionState::NeedsRegister);
    session.send_session_dc_signal(
        ticket,
        success,
        "Deregistration occurred. Session disconnected",
    );

    Ok(ret)
}

async fn deregister_from_hyperlan_server_as_client<R: Ratchet>(
    session_cid: u64,
    session_ref: &CitadelSession<R>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session_ref;
    let (acc_manager, dereg_ticket) = {
        let state_container = inner_state!(session.state_container);
        let acc_manager = session.account_manager.clone();
        //let fcm_client = acc_manager.fcm_client().clone();
        let dereg_ticket = state_container.deregister_state.current_ticket;

        (acc_manager, dereg_ticket)
    };

    let success = match acc_manager.delete_client_by_cid(session_cid).await {
        Ok(_) => {
            log::trace!(target: "citadel", "Successfully purged account {} locally!", session_cid);
            true
        }

        Err(err) => {
            log::error!(target: "citadel", "Unable to locally purge account {}. Please report this to the HyperLAN Server admin. Reason: {:?}", session_cid, err);
            false
        }
    };

    session.send_to_kernel(NodeResult::DeRegistration(DeRegistration {
        session_cid,
        ticket_opt: dereg_ticket,
        success: true,
    }))?;

    session.send_session_dc_signal(
        dereg_ticket,
        success,
        "Deregistration occurred. Session disconnected",
    );

    session.shutdown();

    Ok(PrimaryProcessorResult::Void)
}
