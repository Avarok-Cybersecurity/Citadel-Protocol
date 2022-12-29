use super::includes::*;
use crate::error::NetworkError;
use crate::prelude::ReKeyReturnType;
use crate::proto::node::SecrecyMode;
use crate::proto::packet_crafter::peer_cmd::C2S_ENCRYPTION_ONLY;
use crate::proto::packet_processor::header_to_vconn_type;
use crate::proto::packet_processor::primary_group_packet::{
    attempt_kem_as_alice_finish, attempt_kem_as_bob, get_proper_hyper_ratchet,
    get_resp_target_cid_from_header, ToolsetUpdate,
};
use citadel_crypt::stacked_ratchet::constructor::{AliceToBobTransferType, ConstructorType};
use citadel_crypt::stacked_ratchet::RatchetType;
use std::ops::Deref;
use std::sync::atomic::Ordering;

#[cfg_attr(feature = "localhost-testing", tracing::instrument(target = "citadel", skip_all, ret, err, fields(is_server = session.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get())))]
pub fn process_rekey(
    session: &HdpSession,
    packet: HdpPacket,
    header_drill_vers: u32,
    proxy_cid_info: Option<(u64, u64)>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    if session.state.load(Ordering::Relaxed) != SessionState::Connected {
        log::error!(target: "citadel", "Session state is not connected; dropping drill update packet");
        return Ok(PrimaryProcessorResult::Void);
    }

    let HdpSessionInner {
        state_container,
        time_tracker,
        ..
    } = session.inner.deref();

    let (header, payload, _, _) = packet.decompose();
    let mut state_container = inner_mut_state!(state_container);

    let hyper_ratchet = return_if_none!(
        get_proper_hyper_ratchet(header_drill_vers, &state_container, proxy_cid_info),
        "Unable to get proper HR"
    );
    let (header, payload) = return_if_none!(
        validation::aead::validate_custom(&hyper_ratchet, &header, payload),
        "Unable to validate packet"
    );
    let payload = &payload[..];

    let security_level = header.security_level.into();
    let timestamp = time_tracker.get_global_time_ns();

    match header.cmd_aux {
        // Bob
        packet_flags::cmd::aux::do_drill_update::STAGE0 => {
            log::trace!(target: "citadel", "DO_DRILL_UPDATE STAGE 0 PACKET RECV");
            match validation::do_drill_update::validate_stage0(payload) {
                Some(transfer) => {
                    let resp_target_cid = get_resp_target_cid_from_header(&header);
                    let status = return_if_none!(
                        attempt_kem_as_bob(
                            resp_target_cid,
                            &header,
                            Some(AliceToBobTransferType::Default(transfer)),
                            &mut state_container,
                            &hyper_ratchet
                        ),
                        "Unable to attempt KEM as Bob"
                    );
                    let packet = packet_crafter::do_drill_update::craft_stage1(
                        &hyper_ratchet,
                        status,
                        timestamp,
                        resp_target_cid,
                        security_level,
                    );
                    Ok(PrimaryProcessorResult::ReplyToSender(packet))
                }

                _ => {
                    log::error!(target: "citadel", "Invalid stage0 DO_DRILL_UPDATE packet");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        // Alice
        packet_flags::cmd::aux::do_drill_update::STAGE1 => {
            log::trace!(target: "citadel", "DO_DRILL_UPDATE STAGE 1 PACKET RECV");
            match validation::do_drill_update::validate_stage1(payload) {
                Some(transfer) => {
                    //let mut state_container = inner_mut!(session.state_container);
                    let peer_cid = header.session_cid.get();
                    let target_cid = header.target_cid.get();
                    let resp_target_cid = get_resp_target_cid_from_header(&header);
                    let needs_truncate = transfer.update_status.requires_truncation();
                    let constructor = if target_cid != C2S_ENCRYPTION_ONLY {
                        return_if_none!(state_container
                            .ratchet_update_state
                            .p2p_updates
                            .remove(&peer_cid))
                    } else {
                        return_if_none!(state_container
                            .ratchet_update_state
                            .alice_hyper_ratchet
                            .take())
                    };
                    log::trace!(target: "citadel", "Obtained constructor for {}", resp_target_cid);
                    let secrecy_mode = return_if_none!(state_container
                        .session_security_settings
                        .as_ref()
                        .map(|r| r.secrecy_mode));

                    let needs_early_kernel_alert = transfer.update_status.omitted();

                    let latest_hr = return_if_none!(return_if_none!(
                        attempt_kem_as_alice_finish(
                            secrecy_mode,
                            peer_cid,
                            target_cid,
                            transfer.update_status,
                            &mut state_container,
                            Some(ConstructorType::Default(constructor))
                        )
                        .ok(),
                        "Unable to attempt KEM as alice finish"
                    )
                    .unwrap_or(RatchetType::Default(hyper_ratchet))
                    .assume_default());
                    let truncate_packet = packet_crafter::do_drill_update::craft_truncate(
                        &latest_hr,
                        needs_truncate,
                        resp_target_cid,
                        timestamp,
                        security_level,
                    );

                    if needs_truncate.is_none() || needs_early_kernel_alert {
                        // we only alert the user once truncate_ack received
                        state_container.ratchet_update_state.on_complete(
                            header_to_vconn_type(&header),
                            &session.kernel_tx,
                            ReKeyReturnType::Success {
                                version: latest_hr.version(),
                            },
                        )?;
                    }

                    Ok(PrimaryProcessorResult::ReplyToSender(truncate_packet))
                }

                _ => {
                    log::error!(target: "citadel", "Invalid stage1 DO_DRILL_UPDATE packet");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        // Bob will always receive this, whether the toolset being upgraded or not. This allows Bob to begin using the latest drill version
        packet_flags::cmd::aux::do_drill_update::TRUNCATE => {
            log::trace!(target: "citadel", "DO_DRILL_UPDATE TRUNCATE PACKET RECV");
            let truncate_packet = return_if_none!(
                validation::do_drill_update::validate_truncate(payload),
                "Invalid truncate"
            );
            let resp_target_cid = get_resp_target_cid_from_header(&header);

            let (mut method, secrecy_mode) = if resp_target_cid != C2S_ENCRYPTION_ONLY {
                let endpoint_container = return_if_none!(return_if_none!(state_container
                    .active_virtual_connections
                    .get_mut(&resp_target_cid))
                .endpoint_container
                .as_mut());
                let crypt = &mut endpoint_container.endpoint_crypto;
                let local_cid = header.target_cid.get();
                (
                    ToolsetUpdate::E2E { crypt, local_cid },
                    endpoint_container.default_security_settings.secrecy_mode,
                )
            } else {
                let secrecy_mode = state_container
                    .session_security_settings
                    .as_ref()
                    .map(|r| r.secrecy_mode)
                    .unwrap();
                let crypt = &mut state_container
                    .c2s_channel_container
                    .as_mut()
                    .unwrap()
                    .peer_session_crypto;
                let local_cid = header.session_cid.get();
                (ToolsetUpdate::E2E { crypt, local_cid }, secrecy_mode)
            };

            // We optionally deregister at this endpoint to prevent any further packets with this version from being sent
            if let Some(truncate_vers) = truncate_packet.truncate_version {
                match method.deregister(truncate_vers) {
                    Ok(_) => {
                        log::trace!(target: "citadel", "[Toolset Update] Successfully truncated version {}", truncate_vers)
                    }
                    Err(err) => {
                        log::error!(target: "citadel", "[Toolset Update] Error truncating vers {}: {:?}", truncate_vers, err);
                    }
                }
            }

            // We update the internal latest version usable
            method.post_stage1_alice_or_bob();

            let lock_set_by_alice = return_if_none!(method.unlock(false)).1;

            // if lock set by bob, do poll
            let do_poll = lock_set_by_alice.map(|r| !r).unwrap_or(false);

            // If we didn't have to deregister, then our job is done. alice does not need to hear from Bob
            // But, if deregistration occured, we need to alert alice that way she can unlock hers
            if let Some(truncate_vers) = truncate_packet.truncate_version {
                let truncate_ack = packet_crafter::do_drill_update::craft_truncate_ack(
                    &hyper_ratchet,
                    truncate_vers,
                    resp_target_cid,
                    timestamp,
                    security_level,
                );
                session.send_to_primary_stream(None, truncate_ack)?;
            }

            //std::mem::drop(state_container);

            if secrecy_mode == SecrecyMode::Perfect && do_poll {
                let _ = state_container.poll_next_enqueued(resp_target_cid)?;
            }

            Ok(PrimaryProcessorResult::Void)
        }

        packet_flags::cmd::aux::do_drill_update::TRUNCATE_ACK => {
            log::trace!(target: "citadel", "DO_DRILL_UPDATE TRUNCATE_ACK PACKET RECV");
            let truncate_ack_packet = return_if_none!(
                validation::do_drill_update::validate_truncate_ack(payload),
                "Unable to validate truncate ack"
            );
            log::trace!(target: "citadel", "Adjacent node has finished deregistering version {}", truncate_ack_packet.truncated_version);

            let resp_target_cid = get_resp_target_cid_from_header(&header);

            let (mut method, secrecy_mode) = if resp_target_cid != C2S_ENCRYPTION_ONLY {
                let endpoint_container = return_if_none!(return_if_none!(state_container
                    .active_virtual_connections
                    .get_mut(&resp_target_cid))
                .endpoint_container
                .as_mut());
                let crypt = &mut endpoint_container.endpoint_crypto;
                let local_cid = header.target_cid.get();
                (
                    ToolsetUpdate::E2E { crypt, local_cid },
                    endpoint_container.default_security_settings.secrecy_mode,
                )
            } else {
                let secrecy_mode = state_container
                    .session_security_settings
                    .as_ref()
                    .map(|r| r.secrecy_mode)
                    .unwrap();
                let crypt = &mut state_container
                    .c2s_channel_container
                    .as_mut()
                    .unwrap()
                    .peer_session_crypto;
                let local_cid = header.session_cid.get();
                (ToolsetUpdate::E2E { crypt, local_cid }, secrecy_mode)
            };

            let _ = return_if_none!(method.unlock(true)); // unconditional unlock

            // now, we can poll any packets
            //std::mem::drop(state_container);
            if secrecy_mode == SecrecyMode::Perfect {
                let _ = state_container.poll_next_enqueued(resp_target_cid)?;
            }

            state_container.ratchet_update_state.on_complete(
                header_to_vconn_type(&header),
                &session.kernel_tx,
                ReKeyReturnType::Success {
                    version: hyper_ratchet.version(),
                },
            )?;

            Ok(PrimaryProcessorResult::Void)
        }

        _ => {
            log::error!(target: "citadel", "Invalid auxiliary command for DO_DRILL_UPDATE packet. Dropping");
            Ok(PrimaryProcessorResult::Void)
        }
    }
}
