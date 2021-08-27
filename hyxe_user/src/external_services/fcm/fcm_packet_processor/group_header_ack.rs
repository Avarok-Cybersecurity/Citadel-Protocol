use hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_crypt::endpoint_crypto_container::{PeerSessionCrypto, KemTransferStatus, EndpointRatchetConstructor};
use zerocopy::LayoutVerified;
use crate::external_services::fcm::data_structures::{FcmHeader, FcmTicket};
use crate::external_services::fcm::fcm_packet_processor::{FcmProcessorResult, FcmResult, InstanceParameter};
use std::collections::HashMap;
use hyxe_crypt::hyper_ratchet::constructor::ConstructorType;
use crate::misc::{AccountError, EmptyOptional};

pub async fn process<'a, R: Ratchet, Fcm: Ratchet>(svc_params: InstanceParameter<'a>, endpoint_crypto: &'a mut PeerSessionCrypto<Fcm>, constructors: &mut HashMap<u64, ConstructorType<R, Fcm>>, header: LayoutVerified<&'a [u8], FcmHeader>, bob_to_alice_transfer: KemTransferStatus) -> Result<FcmProcessorResult, AccountError> {
    log::info!("FCM RECV GROUP_HEADER_ACK");
    let mut instance = svc_params.create_instance(endpoint_crypto)?;
    let peer_cid = header.session_cid.get();
    let local_cid = header.target_cid.get();

    let update_ocurred = bob_to_alice_transfer.has_some();
    let requires_truncation = bob_to_alice_transfer.requires_truncation();

    let next_ratchet: Option<&Fcm> = match bob_to_alice_transfer {
        KemTransferStatus::Some(transfer, ..) => {
            if let Some(ConstructorType::Fcm(mut constructor)) = constructors.remove(&peer_cid) {
                if let None = constructor.stage1_alice(&transfer) {
                    return Err(AccountError::msg("Unable to construct hyper ratchet"))
                }

                if let Err(_) = endpoint_crypto.update_sync_safe(constructor, true, local_cid) {
                    return Err(AccountError::msg("Unable to update container (X-01b)"))
                }

                if let Some(version) = requires_truncation {
                    if let Err(err) = endpoint_crypto.deregister_oldest_hyper_ratchet(version) {
                        return Err(AccountError::msg(format!("[Toolset Update/deregister] Unable to update Alice's toolset: {:?}", err).as_str()))
                    }
                }

                endpoint_crypto.post_alice_stage1_or_post_stage1_bob();
                // we unlock only upon getting the truncate ack. This helps prevent an unnecessary amount of packets from being sent outbound too early
                Some(endpoint_crypto.get_hyper_ratchet(None).map_empty_err()?)
                /*
                if requires_truncation.is_some() {
                    // we unlock once we get the truncate ack
                    Some(endpoint_crypto.get_hyper_ratchet(None)?)
                } else {
                    Some(endpoint_crypto.maybe_unlock(true)?)
                }*/
            } else {
                log::warn!("No constructor, yet, KemTransferStatus is Some?? (did KEM constructor not get sent when the initial message got sent out?)");
                None
            }
        }

        KemTransferStatus::Omitted => {
            log::warn!("KEM was omitted (is adjacent node's hold not being released (unexpected), or tight concurrency (expected)?)");
            Some(endpoint_crypto.maybe_unlock(true).map_empty_err()?)
        }

        KemTransferStatus::StatusNoTransfer(_status) => {
            log::error!("Unaccounted program logic @ StatusNoTransfer. Report to developers");
            None
        }

        _ => {
            log::info!("[Empty] reached (x-12b)");
            None
        }
    };

    if update_ocurred {
        if let Some(ratchet) = next_ratchet {
            // send TRUNCATE packet
            let truncate_packet = super::super::fcm_packet_crafter::craft_truncate(ratchet, header.object_id.get(), header.group_id.get(), peer_cid, header.ticket.get(), requires_truncation);
            instance.send(truncate_packet, local_cid, peer_cid).await?;
        } else {
            log::error!("No ratchet returned when one was expected");
        }
    }

    log::info!("SUBROUTINE COMPLETE: PROCESS GROUP_HEADER_ACK");
    Ok(FcmProcessorResult::Value(FcmResult::GroupHeaderAck { ticket: FcmTicket::new(header.target_cid.get(), header.session_cid.get(), header.ticket.get()) }))
}