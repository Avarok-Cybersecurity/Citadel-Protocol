use super::includes::*;
use crate::constants::GROUP_EXPIRE_TIME_MS;
use crate::error::NetworkError;
use crate::functional::IfTrueConditional;
use crate::inner_arg::ExpectedInnerTarget;
use crate::prelude::InternalServerError;
use crate::proto::node_result::OutboundRequestRejected;
use crate::proto::packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
use crate::proto::session_queue_handler::QueueWorkerResult;
use crate::proto::state_container::{FileKey, GroupKey, StateContainerInner};
use crate::proto::validation::group::{GroupHeader, GroupHeaderAck, WaveAck};
use citadel_crypt::endpoint_crypto_container::{
    EndpointRatchetConstructor, KemTransferStatus, PeerSessionCrypto,
};
use citadel_crypt::fcm::fcm_ratchet::ThinRatchet;
use citadel_crypt::misc::CryptError;
use citadel_crypt::stacked_ratchet::constructor::{AliceToBobTransferType, ConstructorType};
use citadel_crypt::stacked_ratchet::{Ratchet, RatchetType, StackedRatchet};
use citadel_types::crypto::SecrecyMode;
use citadel_types::proto::UdpMode;
use std::ops::Deref;
use std::sync::atomic::Ordering;

/// This will handle an inbound primary group packet
/// NOTE: Since incorporating the proxy features, if a packet gets to this process closure, it implies the packet
/// has reached its destination. Just need to ensure that intermediary packets get the proper target_cid on the headers that way
/// they proxy
///
/// `proxy_cid_info`: is None if the packets were not proxied, and will thus use the session's pqcrypto to authenticate the data.
/// If `proxy_cid_info` is Some, then a tuple of the original implicated cid (peer cid) and the original target cid (this cid)
/// will be provided. In this case, we must use the virtual conn's crypto
#[cfg_attr(feature = "localhost-testing", tracing::instrument(target = "citadel", skip_all, ret, err, fields(is_server = session_ref.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get())))]
pub fn process_primary_packet(
    session_ref: &HdpSession,
    cmd_aux: u8,
    packet: HdpPacket,
    proxy_cid_info: Option<(u64, u64)>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session_ref;

    let HdpSessionInner {
        time_tracker,
        state_container,
        state,
        ..
    } = session.inner.deref();

    if state.load(Ordering::Relaxed) != SessionState::Connected {
        log::warn!(target: "citadel", "Group packet dropped; session not connected");
        return Ok(PrimaryProcessorResult::Void);
    }

    // Group payloads are not validated in the same way the primary packets are (with the exception of FAST_MSG's in GROUP_HEADERS)
    // While group payloads are typically processed by the wave ports, it is possible
    // that TCP_ONLY mode is engaged, in which case, the packets are funneled through here
    let (header, payload, _, _) = packet.decompose();

    let timestamp = time_tracker.get_global_time_ns();

    let mut state_container = inner_mut_state!(state_container);
    let udp_mode = state_container.udp_mode;
    // get the proper pqc
    let header_bytes = &header[..];
    let header = return_if_none!(Ref::new(header_bytes), "Unable to load header [PGP]")
        as Ref<&[u8], HdpHeader>;
    let hyper_ratchet = return_if_none!(
        get_proper_hyper_ratchet(header.drill_version.get(), &state_container, proxy_cid_info),
        "Unable to get proper StackedRatchet [PGP]"
    );
    let security_level = header.security_level.into();
    //log::trace!(target: "citadel", "[Peer StackedRatchet] Obtained version {} w/ CID {} (local CID: {})", hyper_ratchet.version(), hyper_ratchet.get_cid(), header.session_cid.get());
    match header.cmd_aux {
        packet_flags::cmd::aux::group::GROUP_PAYLOAD => {
            log::trace!(target: "citadel", "RECV GROUP PAYLOAD {:?}", header);
            // These packets do not get encrypted with the message key. They get scrambled and encrypted
            match state_container.on_group_payload_received(
                &header,
                payload.freeze(),
                &hyper_ratchet,
            ) {
                Ok(res) => {
                    state_container.meta_expiry_state.on_event_confirmation();
                    Ok(res)
                }

                Err((err, ticket, object_id)) => {
                    log::error!(target: "citadel", "on_group_payload_received error: {:?}", err);
                    // Send an error packet back to the source and send a signal to the handle
                    // TODO: File transfer handle cleanup on failure
                    if let Err(err) = state_container.notify_object_transfer_handle_failure(
                        &header,
                        err.to_string(),
                        object_id,
                    ) {
                        log::error!(target: "citadel", "Unable to notify object transfer handle failure: {err:?}");
                        // Send error to kernel instead
                        session.send_to_kernel(NodeResult::InternalServerError(
                            InternalServerError {
                                ticket_opt: Some(ticket),
                                message: err.to_string(),
                                cid_opt: session.implicated_cid.get(),
                            },
                        ))?;
                    }

                    let v_conn = get_v_conn_from_header(&header);

                    // Finally, alert the adjacent endpoint by crafting an error packet
                    let error_packet = packet_crafter::file::craft_file_error_packet(
                        &hyper_ratchet,
                        ticket,
                        security_level,
                        v_conn,
                        timestamp,
                        err.into_string(),
                        object_id,
                    );
                    Ok(PrimaryProcessorResult::ReplyToSender(error_packet))
                }
            }
        }

        _ => {
            match validation::aead::validate_custom(&hyper_ratchet, &*header, payload) {
                Some((header, mut payload)) => {
                    state_container.meta_expiry_state.on_event_confirmation();
                    match cmd_aux {
                        packet_flags::cmd::aux::group::GROUP_HEADER => {
                            log::trace!(target: "citadel", "RECV GROUP HEADER");
                            let is_message = header.algorithm == 1;
                            if is_message {
                                let (plaintext, transfer, object_id) = return_if_none!(
                                    validation::group::validate_message(&mut payload),
                                    "Bad message packet"
                                );
                                log::trace!(target: "citadel", "Recv FastMessage. version {} w/ CID {} (local CID: {})", hyper_ratchet.version(), hyper_ratchet.get_cid(), header.session_cid.get());
                                // Here, we do not go through all the fiasco like above. We just forward the message to the kernel, then send an ACK
                                // so that the sending side can be notified of a successful send
                                let resp_target_cid = get_resp_target_cid_from_header(&header);
                                log::trace!(target: "citadel", "Resp target cid {} obtained. version {} w/ CID {} (local CID: {})", resp_target_cid, hyper_ratchet.version(), hyper_ratchet.get_cid(), header.session_cid.get());
                                let ticket = header.context_info.get().into();
                                // we call this to ensure a flood of these packets doesn't cause ordinary groups from being dropped

                                // now, update the keys (if applicable)
                                let transfer = return_if_none!(
                                    attempt_kem_as_bob(
                                        resp_target_cid,
                                        &header,
                                        transfer.map(AliceToBobTransferType::Default),
                                        &mut state_container,
                                        &hyper_ratchet
                                    ),
                                    "Unable to attempt_kem_as_bob [PGP]"
                                );

                                let target_cid =
                                    if let Some((original_implicated_cid, _original_target_cid)) =
                                        proxy_cid_info
                                    {
                                        original_implicated_cid
                                    } else {
                                        0
                                    };

                                if !state_container.forward_data_to_ordered_channel(
                                    target_cid,
                                    header.group.get(),
                                    plaintext,
                                ) {
                                    log::error!(target: "citadel", "Unable to forward data to channel (peer: {})", target_cid);
                                    return Ok(PrimaryProcessorResult::Void);
                                }

                                let group_header_ack =
                                    packet_crafter::group::craft_group_header_ack(
                                        &hyper_ratchet,
                                        header.group.get(),
                                        resp_target_cid,
                                        object_id,
                                        ticket,
                                        None,
                                        true,
                                        timestamp,
                                        transfer,
                                        security_level,
                                    );
                                Ok(PrimaryProcessorResult::ReplyToSender(group_header_ack))
                            } else {
                                let group_header = return_if_none!(
                                    validation::group::validate_header(&payload),
                                    "Bad non-message group header"
                                );
                                match group_header {
                                    GroupHeader::Standard(
                                        group_receiver_config,
                                        virtual_target,
                                    ) => {
                                        // First, check to make sure the virtual target can accept
                                        let object_id = group_receiver_config.object_id;
                                        let ticket = header.context_info.get().into();

                                        //let sess_implicated_cid = session.implicated_cid.load(Ordering::Relaxed)?;
                                        //let target_cid_header = header.target_cid.get();
                                        // for HyperLAN conns, this is true

                                        let resp_target_cid = return_if_none!(
                                            get_resp_target_cid(&virtual_target),
                                            "Unable to get resp_target_cid [PGP]"
                                        );

                                        // the below will return None if not ready to accept
                                        let initial_wave_window = state_container
                                            .on_group_header_received(
                                                &header,
                                                group_receiver_config,
                                                virtual_target,
                                            );
                                        if initial_wave_window.is_some() {
                                            // register group timeout device
                                            //std::mem::drop(state_container);
                                            let group_id = header.group.get();
                                            let peer_cid = header.session_cid.get();

                                            session.queue_handle.insert_ordinary(group_id as usize, peer_cid, GROUP_EXPIRE_TIME_MS, move |state_container| {
                                                let key = GroupKey::new(peer_cid, group_id, object_id);
                                                if let Some(group) = state_container.inbound_groups.get(&key) {
                                                    if group.has_begun {
                                                        if group.receiver.has_expired(GROUP_EXPIRE_TIME_MS) {
                                                            if state_container.meta_expiry_state.expired() {
                                                                log::error!(target: "citadel", "Inbound group {} has expired; removing for {}.", group_id, peer_cid);
                                                                if let Some(group) = state_container.inbound_groups.remove(&key) {
                                                                    if group.object_id != 0 {
                                                                        // belongs to a file. Delete file; stop transmission
                                                                        let key = FileKey::new(peer_cid, group.object_id);
                                                                        if let Some(_file) = state_container.inbound_files.remove(&key) {
                                                                            // dropping this will automatically drop the future streaming to HD
                                                                            log::warn!(target: "citadel", "File transfer expired");
                                                                            // TODO: Create file FIN
                                                                        }

                                                                        let _ = state_container.file_transfer_handles.remove(&key);
                                                                    }
                                                                }

                                                                QueueWorkerResult::Complete
                                                            } else {
                                                                log::trace!(target: "citadel", "Other inbound groups being processed; patiently awaiting group {}", group_id);
                                                                QueueWorkerResult::Incomplete
                                                            }
                                                        } else {
                                                            // The inbound group is still receiving, and it hasn't expired. Keep polling
                                                            QueueWorkerResult::Incomplete
                                                        }
                                                    } else {
                                                        // group has not started; previous group is still transferring. Do no interrupt transfer
                                                        QueueWorkerResult::Incomplete
                                                    }
                                                } else {
                                                    // has been removed, thus is complete
                                                    QueueWorkerResult::Complete
                                                }
                                            });
                                        }

                                        let group_header_ack =
                                            packet_crafter::group::craft_group_header_ack(
                                                &hyper_ratchet,
                                                header.group.get(),
                                                resp_target_cid,
                                                object_id,
                                                ticket,
                                                initial_wave_window,
                                                false,
                                                timestamp,
                                                KemTransferStatus::Empty,
                                                security_level,
                                            );
                                        Ok(PrimaryProcessorResult::ReplyToSender(group_header_ack))
                                    }
                                }
                            }
                        }

                        packet_flags::cmd::aux::group::GROUP_HEADER_ACK => {
                            log::trace!(target: "citadel", "RECV GROUP HEADER ACK");
                            match validation::group::validate_header_ack(&payload) {
                                Some(GroupHeaderAck::ReadyToReceive {
                                    initial_window,
                                    transfer,
                                    fast_msg,
                                    object_id,
                                }) => {
                                    // we need to begin sending the data
                                    // valid and ready to accept!
                                    let initial_wave_window = if udp_mode == UdpMode::Disabled {
                                        None
                                    } else {
                                        initial_window
                                    };

                                    let resp_target_cid = get_resp_target_cid_from_header(&header);
                                    let peer_cid = header.session_cid.get();
                                    //let mut state_container = session.state_container.borrow_mut();
                                    let group_id = header.group.get();

                                    let target_cid = header.target_cid.get();
                                    let needs_truncate = transfer.requires_truncation();

                                    let transfer_occurred = transfer.has_some();
                                    let secrecy_mode = return_if_none!(
                                        state_container
                                            .session_security_settings
                                            .as_ref()
                                            .map(|r| r.secrecy_mode),
                                        "Unable to get secrecy mode [PGP]"
                                    );

                                    if resp_target_cid != C2S_ENCRYPTION_ONLY {
                                        // If there is a pending disconnect, we need to make sure the session gets dropped until after all packets get processed
                                        let vconn = return_if_none!(
                                            state_container
                                                .active_virtual_connections
                                                .get(&resp_target_cid),
                                            "Vconn not loaded"
                                        );
                                        vconn
                                            .last_delivered_message_timestamp
                                            .set(Some(Instant::now()));
                                    }

                                    // TODO: make the below function return a result, not bools
                                    if state_container.on_group_header_ack_received(
                                        secrecy_mode,
                                        peer_cid,
                                        target_cid,
                                        group_id,
                                        object_id,
                                        initial_wave_window,
                                        transfer,
                                        fast_msg,
                                    ) {
                                        //std::mem::drop(state_container);
                                        log::trace!(target: "citadel", "[Toolset Update] Needs truncation? {:?}", &needs_truncate);

                                        //session.send_to_kernel(HdpServerResult::MessageDelivered(header.context_info.get().into()))?;
                                        // now, we need to do one last thing. We need to send a truncate packet to at least allow bob to begin sending packets using the latest HR
                                        // we need to send a truncate packet. BUT, only if the package was SOME. Just b/c it is some does not mean a truncation is necessary
                                        if transfer_occurred {
                                            let target_cid = if target_cid != C2S_ENCRYPTION_ONLY {
                                                peer_cid
                                            } else {
                                                C2S_ENCRYPTION_ONLY
                                            };
                                            let truncate_packet =
                                                packet_crafter::do_drill_update::craft_truncate(
                                                    &hyper_ratchet,
                                                    needs_truncate,
                                                    target_cid,
                                                    timestamp,
                                                    security_level,
                                                );
                                            log::trace!(target: "citadel", "About to send TRUNCATE packet to MAYBE remove v {:?} | HR v {} | HR CID {}", needs_truncate, hyper_ratchet.version(), hyper_ratchet.get_cid());
                                            session
                                                .send_to_primary_stream(None, truncate_packet)?;
                                        }

                                        //std::mem::drop(state_container);

                                        // if a transfer occurred, we will get polled once we get an TRUNCATE_ACK. No need to double poll
                                        if secrecy_mode == SecrecyMode::Perfect {
                                            log::trace!(target: "citadel", "Polling next in pgp");
                                            let _ = state_container
                                                .poll_next_enqueued(resp_target_cid)?;
                                        }

                                        Ok(PrimaryProcessorResult::Void)
                                    } else if udp_mode == UdpMode::Disabled {
                                        Ok(PrimaryProcessorResult::EndSession(
                                            "TCP sockets disconnected",
                                        ))
                                    } else {
                                        Ok(PrimaryProcessorResult::EndSession(
                                            "UDP sockets disconnected",
                                        ))
                                    }
                                }

                                Some(GroupHeaderAck::NotReady {
                                    fast_msg,
                                    object_id,
                                }) => {
                                    // valid but not ready to accept.
                                    // Possible reasons: too large, target not valid (e.g., not registered, not connected, etc)
                                    //let mut state_container = session.state_container.borrow_mut();
                                    let group = header.group.get();
                                    let key =
                                        GroupKey::new(header.session_cid.get(), group, object_id);
                                    if state_container.outbound_transmitters.remove(&key).is_none()
                                    {
                                        log::error!(target: "citadel", "Unable to remove outbound transmitter for group {} (non-existent)", group);
                                    }
                                    //std::mem::drop(state_container);

                                    if !fast_msg {
                                        let ticket = header.context_info.get();
                                        log::trace!(target: "citadel", "Header ACK was valid, but the receiving end is not receiving the packet at this time. Clearing local memory ...");
                                        session.send_to_kernel(
                                            NodeResult::OutboundRequestRejected(
                                                OutboundRequestRejected {
                                                    ticket: ticket.into(),
                                                    message_opt: Some(Vec::from(
                                                        "Adjacent node unable to accept request",
                                                    )),
                                                },
                                            ),
                                        )?;
                                    }

                                    Ok(PrimaryProcessorResult::Void)
                                }

                                None => {
                                    // invalid packet
                                    log::error!(target: "citadel", "Invalid GROUP HEADER ACK");
                                    Ok(PrimaryProcessorResult::Void)
                                }
                            }
                        }

                        packet_flags::cmd::aux::group::WAVE_ACK => {
                            log::trace!(target: "citadel", "RECV WAVE ACK");
                            match validation::group::validate_wave_ack(&payload) {
                                Some(WaveAck { range }) => {
                                    if range.is_some() {
                                        log::trace!(target: "citadel", "WAVE_ACK implies window completion");
                                    }

                                    // the window is done. Since this node is the transmitter, we then make a call to begin sending the next wave
                                    if !state_container
                                        .on_wave_ack_received(hyper_ratchet.get_cid(), &header)
                                    {
                                        if udp_mode == UdpMode::Disabled {
                                            log::error!(target: "citadel", "There was an error sending the TCP window; Cancelling connection");
                                        } else {
                                            log::error!(target: "citadel", "There was an error sending the UDP window; Cancelling connection");
                                        }

                                        Ok(PrimaryProcessorResult::EndSession(
                                            "Sockets disconnected",
                                        ))
                                    } else {
                                        log::trace!(target: "citadel", "Successfully sent next window in response to WAVE ACK");
                                        Ok(PrimaryProcessorResult::Void)
                                    }
                                }

                                None => {
                                    log::error!(target: "citadel", "Error validating WAVE_ACK");
                                    Ok(PrimaryProcessorResult::Void)
                                }
                            }
                        }

                        _ => {
                            log::trace!(target: "citadel", "Primary port GROUP packet has an invalid auxiliary command. Dropping");
                            Ok(PrimaryProcessorResult::Void)
                        }
                    }
                }

                _ => {
                    log::warn!(target: "citadel", "Packet failed AES-GCM validation stage (self node: {})", session.is_server.if_true("server").if_false("client"));
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }
    }
}

#[inline]
pub(super) fn get_proper_hyper_ratchet(
    header_drill_vers: u32,
    state_container: &dyn ExpectedInnerTarget<StateContainerInner>,
    proxy_cid_info: Option<(u64, u64)>,
) -> Option<StackedRatchet> {
    if let Some((original_implicated_cid, _original_target_cid)) = proxy_cid_info {
        // since this conn was proxied, we need to go into the virtual conn layer to get the peer session crypto. HOWEVER:
        // In the case that a packet is proxied back to the source, the adjacent endpoint inscribes this node's cid
        // inside the target_cid (that way the packet routes correctly to this node). However, this is problematic here
        // since we use the original implicated CID
        if let Some(vconn) = state_container
            .active_virtual_connections
            .get(&original_implicated_cid)
        {
            //log::trace!(target: "citadel", "[Peer StackedRatchet] v{} from vconn w/ {}", header_drill_vers, original_implicated_cid);
            vconn
                .borrow_endpoint_hyper_ratchet(Some(header_drill_vers))
                .cloned()
        } else {
            log::warn!(target: "citadel", "Unable to find vconn for {}. Unable to process primary group packet", original_implicated_cid);
            None
        }
    } else {
        // since this was not proxied, use the ordinary pqc and drill
        if state_container.state.load(Ordering::Relaxed) != SessionState::Connected {
            state_container.pre_connect_state.generated_ratchet.clone()
        } else {
            state_container
                .c2s_channel_container
                .as_ref()?
                .peer_session_crypto
                .get_hyper_ratchet(Some(header_drill_vers))
                .cloned()
        }
    }
}

/// returns the relative `resp_target_cid`
pub fn get_resp_target_cid(virtual_target: &VirtualConnectionType) -> Option<u64> {
    match virtual_target {
        VirtualConnectionType::LocalGroupPeer {
            implicated_cid,
            peer_cid: _target_cid,
        } => {
            // by logic of the network, target_cid must equal this node's CID
            // since we have entered this process function
            //debug_assert_eq!(sess_implicated_cid, target_cid);
            //debug_assert_eq!(target_cid_header, target_cid);
            Some(*implicated_cid)
        }

        VirtualConnectionType::LocalGroupServer {
            implicated_cid: _implicated_cid,
        } => {
            // Since this is the receiving node, and we are already in a valid connection, return true
            Some(0) // ZERO, since we don't use ordinary p2p encryption
        }

        _ => {
            log::error!(target: "citadel", "HyperWAN functionality is not yet implemented");
            None
        }
    }
}

pub fn get_resp_target_cid_from_header(header: &HdpHeader) -> u64 {
    if header.target_cid.get() != C2S_ENCRYPTION_ONLY {
        header.session_cid.get()
    } else {
        C2S_ENCRYPTION_ONLY
    }
}

#[allow(unused)]
pub enum ToolsetUpdate<'a> {
    E2E {
        crypt: &'a mut PeerSessionCrypto<StackedRatchet>,
        local_cid: u64,
    },
    Fcm {
        fcm_crypt_container: &'a mut PeerSessionCrypto<ThinRatchet>,
        peer_cid: u64,
        local_cid: u64,
    },
}

impl ToolsetUpdate<'_> {
    pub(crate) fn update(
        &mut self,
        constructor: ConstructorType<StackedRatchet, ThinRatchet>,
        local_is_alice: bool,
    ) -> Result<KemTransferStatus, CryptError> {
        match self {
            ToolsetUpdate::E2E { crypt, local_cid } => {
                let constructor = constructor.assume_default().ok_or_else(|| {
                    CryptError::DrillUpdateError("Constructor is not default type".to_string())
                })?;
                crypt.update_sync_safe(constructor, local_is_alice, *local_cid)
            }

            ToolsetUpdate::Fcm {
                fcm_crypt_container,
                local_cid,
                ..
            } => {
                let constructor = constructor.assume_fcm().ok_or_else(|| {
                    CryptError::DrillUpdateError("Constructor is not FCM type".to_string())
                })?;
                fcm_crypt_container.update_sync_safe(constructor, local_is_alice, *local_cid)
            }
        }
    }

    /// This should only be called after an update
    pub(crate) fn post_stage1_alice_or_bob(&mut self) {
        match self {
            ToolsetUpdate::E2E { crypt, .. } => {
                crypt.post_alice_stage1_or_post_stage1_bob();
            }

            ToolsetUpdate::Fcm {
                fcm_crypt_container,
                ..
            } => {
                fcm_crypt_container.post_alice_stage1_or_post_stage1_bob();
            }
        }
    }

    pub(crate) fn deregister(&mut self, version: u32) -> Result<(), NetworkError> {
        match self {
            ToolsetUpdate::E2E { crypt, .. } => crypt
                .deregister_oldest_hyper_ratchet(version)
                .map_err(|err| NetworkError::Generic(err.to_string())),

            ToolsetUpdate::Fcm {
                fcm_crypt_container,
                ..
            } => fcm_crypt_container
                .deregister_oldest_hyper_ratchet(version)
                .map_err(|err| NetworkError::Generic(err.to_string())),
        }
    }

    /// Unlocks the internal state, allowing future upgrades to the system. Returns the latest hyper ratchet
    pub(crate) fn unlock(
        &mut self,
        requires_locked_by_alice: bool,
    ) -> Option<(RatchetType<StackedRatchet, ThinRatchet>, Option<bool>)> {
        match self {
            ToolsetUpdate::E2E { crypt, .. } => {
                let lock_src = crypt.lock_set_by_alice;
                crypt
                    .maybe_unlock(requires_locked_by_alice)
                    .map(|r| (RatchetType::Default(r.clone()), lock_src))
            }

            ToolsetUpdate::Fcm {
                fcm_crypt_container,
                ..
            } => {
                let lock_src = fcm_crypt_container.lock_set_by_alice;
                fcm_crypt_container
                    .maybe_unlock(requires_locked_by_alice)
                    .map(|r| (RatchetType::Fcm(r.clone()), lock_src))
            }
        }
    }

    pub(crate) fn get_local_cid(&self) -> u64 {
        match self {
            ToolsetUpdate::E2E { local_cid, .. } => *local_cid,
            ToolsetUpdate::Fcm { local_cid, .. } => *local_cid,
        }
    }

    pub(crate) fn get_latest_ratchet(&self) -> Option<RatchetType<StackedRatchet, ThinRatchet>> {
        match self {
            ToolsetUpdate::E2E { crypt, .. } => crypt
                .get_hyper_ratchet(None)
                .map(|r| RatchetType::Default(r.clone())),

            ToolsetUpdate::Fcm {
                fcm_crypt_container,
                ..
            } => fcm_crypt_container
                .get_hyper_ratchet(None)
                .map(|r| RatchetType::Fcm(r.clone())),
        }
    }
}

/// peer_cid: from header.session_cid
/// target_cid: from header.target_cid
///
/// Returns: Ok(latest_hyper_ratchet)
pub(crate) fn attempt_kem_as_alice_finish(
    base_session_secrecy_mode: SecrecyMode,
    peer_cid: u64,
    target_cid: u64,
    transfer: KemTransferStatus,
    state_container: &mut StateContainerInner,
    constructor: Option<ConstructorType<StackedRatchet, ThinRatchet>>,
) -> Result<Option<RatchetType<StackedRatchet, ThinRatchet>>, ()> {
    let (mut toolset_update_method, secrecy_mode) = if target_cid != C2S_ENCRYPTION_ONLY {
        let endpoint_container = state_container
            .active_virtual_connections
            .get_mut(&peer_cid)
            .ok_or(())?
            .endpoint_container
            .as_mut()
            .ok_or(())?;
        let crypt = &mut endpoint_container.endpoint_crypto;
        (
            ToolsetUpdate::E2E {
                crypt,
                local_cid: target_cid,
            },
            endpoint_container.default_security_settings.secrecy_mode,
        )
    } else {
        let crypt = &mut state_container
            .c2s_channel_container
            .as_mut()
            .unwrap()
            .peer_session_crypto;
        (
            ToolsetUpdate::E2E {
                crypt,
                local_cid: peer_cid,
            },
            base_session_secrecy_mode,
        )
    };

    //let transfer_ocurred = transfer.has_some();
    let requires_truncation = transfer.requires_truncation();

    match transfer {
        KemTransferStatus::Some(transfer, ..) => {
            if let Some(mut constructor) = constructor {
                if let Err(err) = constructor.stage1_alice(transfer) {
                    log::error!(target: "citadel", "Unable to construct hyper ratchet {:?}", err);
                    return Err(()); // return true, otherwise, the session ends
                }

                if let Err(err) = toolset_update_method.update(constructor, true) {
                    log::error!(target: "citadel", "Unable to update container (X-01) | {:?}", err);
                    return Err(());
                }

                if let Some(version) = requires_truncation {
                    if let Err(err) = toolset_update_method.deregister(version) {
                        log::error!(target: "citadel", "[Toolset Update] Unable to update Alice's toolset: {:?}", err);
                        return Err(());
                    }
                }

                // Since alice has updated, and bob has the latest ratchet committed (but not yet able to use it), we can begin sending packets from the latest version to bob
                // in order for bob to begin using the latest version, he needs to receive the TRUNCATE_STATUS packet
                toolset_update_method.post_stage1_alice_or_bob();

                match secrecy_mode {
                    SecrecyMode::Perfect | SecrecyMode::BestEffort => {
                        if requires_truncation.is_some() {
                            // we unlock once we get the truncate ack
                            Ok(Some(toolset_update_method.get_latest_ratchet().ok_or(())?))
                        } else {
                            Ok(Some(toolset_update_method.unlock(true).ok_or(())?.0))
                        }
                    } /*SecrecyMode::BestEffort => {
                          // since we don't unlock on header_acks, we have to unconditionally unlock here
                          Ok(Some(toolset_update_method.unlock(false).ok_or(())?.0))
                      }*/
                }
            } else {
                log::error!(target: "citadel", "No constructor, yet, KemTransferStatus is Some??");
                Ok(None)
            }
        }

        KemTransferStatus::Omitted => match secrecy_mode {
            SecrecyMode::Perfect => Ok(Some(toolset_update_method.unlock(true).ok_or(())?.0)),

            SecrecyMode::BestEffort => Ok(Some(toolset_update_method.unlock(true).ok_or(())?.0)),
        },

        KemTransferStatus::StatusNoTransfer(_status) => {
            log::error!(target: "citadel", "Unaccounted program logic @ StatusNoTransfer! Report to developers");
            Err(())
        }

        _ => Ok(None),
    }
}

/// NOTE! Assumes the `hr` passed is the latest version IF the transfer is some
pub(crate) fn attempt_kem_as_bob(
    resp_target_cid: u64,
    header: &Ref<&[u8], HdpHeader>,
    transfer: Option<AliceToBobTransferType>,
    state_container: &mut StateContainerInner,
    hr: &StackedRatchet,
) -> Option<KemTransferStatus> {
    if let Some(transfer) = transfer {
        let update = if resp_target_cid != C2S_ENCRYPTION_ONLY {
            let crypt = &mut state_container
                .active_virtual_connections
                .get_mut(&resp_target_cid)?
                .endpoint_container
                .as_mut()?
                .endpoint_crypto;
            ToolsetUpdate::E2E {
                crypt,
                local_cid: header.target_cid.get(),
            }
        } else {
            let crypt = &mut state_container
                .c2s_channel_container
                .as_mut()
                .unwrap()
                .peer_session_crypto;
            ToolsetUpdate::E2E {
                crypt,
                local_cid: header.session_cid.get(),
            }
        };

        update_toolset_as_bob(update, transfer, hr)
    } else {
        Some(KemTransferStatus::Empty)
    }
}

pub(crate) fn update_toolset_as_bob(
    mut update_method: ToolsetUpdate<'_>,
    transfer: AliceToBobTransferType,
    hr: &StackedRatchet,
) -> Option<KemTransferStatus> {
    let cid = update_method.get_local_cid();
    let new_version = transfer.get_declared_new_version();
    //let (crypto_params, session_security_level) = transfer.get_security_opts();
    //let opts = ConstructorOpts::new_vec_init(Some(crypto_params), (session_security_level.value() + 1) as usize);
    let opts = hr.get_next_constructor_opts();
    if matches!(transfer, AliceToBobTransferType::Fcm(..)) {
        let constructor =
            EndpointRatchetConstructor::<ThinRatchet>::new_bob(cid, new_version, opts, transfer)?;
        Some(
            update_method
                .update(ConstructorType::Fcm(constructor), false)
                .ok()?,
        )
    } else {
        let constructor = EndpointRatchetConstructor::<StackedRatchet>::new_bob(
            cid,
            new_version,
            opts,
            transfer,
        )?;
        Some(
            update_method
                .update(ConstructorType::Default(constructor), false)
                .ok()?,
        )
    }
}

/// Returns the virtual connection type for the response target cid. Is relative to the current node, not the receiving node
pub fn get_v_conn_from_header(header: &HdpHeader) -> VirtualConnectionType {
    let target_cid = header.session_cid.get();
    let implicated_cid = header.target_cid.get();
    if target_cid != C2S_ENCRYPTION_ONLY {
        VirtualConnectionType::LocalGroupPeer {
            implicated_cid,
            peer_cid: target_cid,
        }
    } else {
        VirtualConnectionType::LocalGroupServer { implicated_cid }
    }
}
