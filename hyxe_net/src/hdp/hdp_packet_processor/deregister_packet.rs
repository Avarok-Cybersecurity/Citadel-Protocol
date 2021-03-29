use super::includes::*;
use atomic::Ordering;
use hyxe_crypt::hyper_ratchet::HyperRatchet;

/// processes a deregister packet. The client must be connected to the HyperLAN Server in order to DeRegister
#[inline]
pub async fn process(session_ref: &HdpSession, packet: HdpPacket) -> PrimaryProcessorResult {
    let session = inner!(session_ref);

    if session.state != SessionState::Connected {
        log::error!("disconnect packet received, but session state is not connected. Must be connected to deregister. Dropping");
        return PrimaryProcessorResult::Void;
    }


    let timestamp = session.time_tracker.get_global_time_ns();
    let cnac = session.cnac.as_ref()?;
    let implicated_cid = cnac.get_id();
    let (header, payload, _, _) = packet.decompose();
    let (header, _payload, hyper_ratchet) = validation::aead::validate(cnac, &header, payload)?;
    let ref header = header;
    let security_level = header.security_level.into();

    match header.cmd_aux {
        packet_flags::cmd::aux::do_deregister::STAGE0 => {
            log::info!("STAGE 0 DEREGISTER PACKET RECV");
            std::mem::drop(session);
            deregister_client_from_self(implicated_cid, session_ref, &hyper_ratchet, timestamp, security_level).await
        }

        packet_flags::cmd::aux::do_deregister::SUCCESS => {
            log::info!("STAGE SUCCESS DEREGISTER PACKET RECV");
            std::mem::drop(session);
            deregister_from_hyperlan_server_as_client(implicated_cid, session_ref).await
        }

        packet_flags::cmd::aux::do_deregister::FAILURE => {
            log::info!("STAGE FAILURE DEREGISTER PACKET RECV");
            let state_container = inner!(session.state_container);
            let ticket = state_container.deregister_state.current_ticket.clone();
            // state_container.deregister_state.on_fail();
            std::mem::drop(state_container);
            let cid = session.implicated_cid.load(Ordering::Relaxed)?;
            session.kernel_tx.unbounded_send(HdpServerResult::DeRegistration(VirtualConnectionType::HyperLANPeerToHyperLANServer(cid), ticket, true, false))?;
            log::error!("Unable to locally purge account {}. Please report this to the HyperLAN Server admin", cid);
            PrimaryProcessorResult::EndSession("Deregistration failure. Closing connection anyways")
        }

        _ => {
            log::error!("Invalid auxiliary command");
            PrimaryProcessorResult::Void
        }
    }
}

async fn deregister_client_from_self(implicated_cid: u64, session_ref: &HdpSession, hyper_ratchet: &HyperRatchet, timestamp: i64, security_level: SecurityLevel) -> PrimaryProcessorResult {
    let session = inner!(session_ref);
    let state_container = inner!(session.state_container);
    let ticket = state_container.deregister_state.current_ticket;

    let acc_manager = session.account_manager.clone();
    std::mem::drop(state_container);
    std::mem::drop(session);

    let (ret, success) = match acc_manager.delete_client_by_cid(implicated_cid).await {
        Ok(_) => {
            log::info!("Successfully purged account {} locally!", implicated_cid);
            let stage_success_packet = hdp_packet_crafter::do_deregister::craft_final(hyper_ratchet, true, timestamp, security_level);
            // At the end of the deregistration phase, the session also ends
            (PrimaryProcessorResult::ReplyToSender(stage_success_packet), true)
        }

        Err(err) => {
            log::error!("Unable to locally purge account {}. Please report this to the HyperLAN Server admin ({:?})", implicated_cid, err);
            let stage_failure_packet = hdp_packet_crafter::do_deregister::craft_final(hyper_ratchet, false, timestamp, security_level);
            (PrimaryProcessorResult::ReplyToSender(stage_failure_packet), false)
        }

    };

    let mut session = inner_mut!(session_ref);

    // This ensures no further packets are processed
    session.state = SessionState::NeedsRegister;
    session.send_to_kernel(HdpServerResult::DeRegistration(VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid), ticket, false, success))?;
    session.needs_close_message.store(false, Ordering::SeqCst);

    ret
}

async fn deregister_from_hyperlan_server_as_client(implicated_cid: u64, session_ref: &HdpSession) -> PrimaryProcessorResult {
    let session = inner!(session_ref);
    let state_container = inner!(session.state_container);
    let acc_manager = session.account_manager.clone();
    let to_kernel = session.kernel_tx.clone();
    let cnac = session.cnac.clone()?;
    let needs_close_message = session.needs_close_message.clone();
    let fcm_client = acc_manager.fcm_client().clone();
    let dereg_ticket = state_container.deregister_state.current_ticket;

    std::mem::drop(state_container);
    std::mem::drop(session);

    if let Err(err) = cnac.fcm_raw_broadcast_to_all_peers(fcm_client, |fcm, peer_cid| hyxe_user::fcm::fcm_packet_crafter::craft_deregistered(fcm, peer_cid, 0)).await {
        log::error!("Error when fcm broadcasting: {:#?}", err);
    }

    let success = match acc_manager.delete_client_by_cid(implicated_cid).await {
        Ok(_) => {
            log::info!("Successfully purged account {} locally!", implicated_cid);
            true
        }

        Err(err) => {
            log::error!("Unable to locally purge account {}. Please report this to the HyperLAN Server admin. Reason: {:?}", implicated_cid, err);
            false
        }
    };

    if let Err(err) = to_kernel.unbounded_send(HdpServerResult::DeRegistration(VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid), dereg_ticket, true, success)) {
        log::warn!("Unable to send to kernel: {:#?}", err);
    }

    needs_close_message.store(false, Ordering::SeqCst);

    PrimaryProcessorResult::EndSession("Session ended after deregistration")
}