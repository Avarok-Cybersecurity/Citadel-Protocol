use super::includes::*;
use atomic::Ordering;
use hyxe_crypt::hyper_ratchet::HyperRatchet;

/// processes a deregister packet. The client must be connected to the HyperLAN Server in order to DeRegister
#[inline]
pub fn process(session_main: &HdpSession, packet: HdpPacket) -> PrimaryProcessorResult {
    let mut session = inner_mut!(session_main);

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

    match header.cmd_aux {
        packet_flags::cmd::aux::do_deregister::STAGE0 => {
            log::info!("STAGE 0 DEREGISTER PACKET RECV");
            deregister_client_from_self(implicated_cid, wrap_inner_mut!(session), &hyper_ratchet, timestamp)
        }

        packet_flags::cmd::aux::do_deregister::SUCCESS => {
            log::info!("STAGE SUCCESS DEREGISTER PACKET RECV");
            deregister_from_hyperlan_server_as_client(implicated_cid, wrap_inner_mut!(session))
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

fn deregister_client_from_self<K: ExpectedInnerTargetMut<HdpSessionInner>>(implicated_cid: u64, mut session: InnerParameterMut<K, HdpSessionInner>, hyper_ratchet: &HyperRatchet, timestamp: i64) -> PrimaryProcessorResult {
    let mut state_container = inner_mut!(session.state_container);
    let ticket = state_container.deregister_state.current_ticket;

    // Reset the internal state to allow other processes to run
    state_container.deregister_state.on_success();
    //let target_cid = state_container.deregister_state.target_cid;
    std::mem::drop(state_container);
    let ref acc_manager = session.account_manager;

    let (ret, success) = if acc_manager.delete_client_by_cid(implicated_cid) {
        log::info!("Successfully purged account {} locally!", implicated_cid);
        let stage_success_packet = hdp_packet_crafter::do_deregister::craft_final(hyper_ratchet, true, timestamp);
        // At the end of the deregistration phase, the session also ends
        (PrimaryProcessorResult::ReplyToSender(stage_success_packet), true)
    } else {
        log::error!("Unable to locally purge account {}. Please report this to the HyperLAN Server admin", implicated_cid);
        let stage_failure_packet = hdp_packet_crafter::do_deregister::craft_final(hyper_ratchet, false, timestamp);
        (PrimaryProcessorResult::ReplyToSender(stage_failure_packet), false)
    };

    // This ensures no further packets are processed
    session.state = SessionState::NeedsRegister;
    session.send_to_kernel(HdpServerResult::DeRegistration(VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid), ticket, false, success))?;
    session.needs_close_message.store(false, Ordering::SeqCst);

    ret
}

fn deregister_from_hyperlan_server_as_client<K: ExpectedInnerTargetMut<HdpSessionInner>>(implicated_cid: u64, session: InnerParameterMut<K, HdpSessionInner>) -> PrimaryProcessorResult {
    let mut state_container = inner_mut!(session.state_container);

    let ticket = state_container.deregister_state.current_ticket.clone();
    state_container.deregister_state.on_success();
    std::mem::drop(state_container);
    let ref acc_manager = session.account_manager;

    let (ret, success) = if acc_manager.delete_client_by_cid(implicated_cid) {
        log::info!("Successfully purged account {} locally!", implicated_cid);

        (PrimaryProcessorResult::EndSession("Session ended after successful deregistration!"), true)
    } else {
        log::error!("Unable to locally purge account {}. Please report this to the HyperLAN Server admin", implicated_cid);
        (PrimaryProcessorResult::EndSession("Session ended after unsuccessful deregistration"), false)
    };

    session.send_to_kernel(HdpServerResult::DeRegistration(VirtualConnectionType::HyperLANPeerToHyperLANServer(implicated_cid), ticket, true, success))?;
    session.needs_close_message.store(false, Ordering::SeqCst);

    ret
}