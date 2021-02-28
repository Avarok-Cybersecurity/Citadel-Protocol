use hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_crypt::endpoint_crypto_container::{PeerSessionCrypto, KemTransferStatus, EndpointRatchetConstructor};
use zerocopy::LayoutVerified;
use crate::fcm::data_structures::{FcmHeader, FcmTicket};
use crate::fcm::fcm_packet_processor::{FcmProcessorResult, FcmResult, block_on_async};
use std::sync::Arc;
use fcm::Client;
use crate::fcm::fcm_instance::FCMInstance;
use std::collections::HashMap;
use hyxe_crypt::hyper_ratchet::constructor::ConstructorType;
use crate::misc::AccountError;

pub fn process<'a, R: Ratchet, Fcm: Ratchet>(client: &Arc<Client>, endpoint_crypto: &'a mut PeerSessionCrypto<Fcm>, constructors: &mut HashMap<u64, ConstructorType<R, Fcm>>, header: LayoutVerified<&'a [u8], FcmHeader>, bob_to_alice_transfer: KemTransferStatus) -> FcmProcessorResult {
    let fcm_instance = FCMInstance::new(endpoint_crypto.fcm_keys.clone()?, client.clone());
    let peer_cid = header.session_cid.get();
    let local_cid = header.target_cid.get();
    let requires_truncation = bob_to_alice_transfer.requires_truncation();

    let next_ratchet: Option<&Fcm> = match bob_to_alice_transfer {
        KemTransferStatus::Some(transfer, ..) => {
            if let Some(ConstructorType::Fcm(mut constructor)) = constructors.remove(&peer_cid) {
                if let None = constructor.stage1_alice(&transfer) {
                    return FcmProcessorResult::Err("Unable to construct hyper ratchet".to_string())
                }

                if let Err(_) = endpoint_crypto.update_sync_safe(constructor, true, local_cid) {
                    return FcmProcessorResult::Err("Unable to update container (X-01b)".to_string())
                }

                if let Some(version) = requires_truncation {
                    if let Err(err) = endpoint_crypto.deregister_oldest_hyper_ratchet(version) {
                        return FcmProcessorResult::Err(format!("[Toolset Update/deregister] Unable to update Alice's toolset: {:?}", err))
                    }
                }

                Some(endpoint_crypto.unlock().ok_or(AccountError::Generic("Unable to unlock crypt container".to_string()))?)
            } else {
                log::warn!("No constructor, yet, KemTransferStatus is Some?? (did KEM constructor not get sent when the initial message got sent out?)");
                None
            }
        }

        KemTransferStatus::Omitted => {
            log::warn!("KEM was omitted (is adjacent node's hold not being released (unexpected), or tight concurrency (expected)?)");
            Some(endpoint_crypto.unlock().ok_or(AccountError::Generic("Unable to unlock crypt container".to_string()))?)
        }

        // in this case, wtf? insomnia OP
        KemTransferStatus::StatusNoTransfer(_status) => {
            log::error!("Unaccounted program logic @ StatusNoTransfer. Report to developers");
            None
        }

        _ => {
            None
        }
    };

    if let Some(truncate_vers) = requires_truncation {
        // send TRUNCATE packet
        let truncate_packet = super::super::fcm_packet_crafter::craft_truncate(next_ratchet?, header.object_id.get(), header.group_id.get(), header.session_cid.get(), header.ticket.get(), truncate_vers);
        let _res = block_on_async(|| async move {
            fcm_instance.send_to_fcm_user(truncate_packet).await
        })??;
    }

    FcmProcessorResult::Value(FcmResult::GroupHeaderAck { ticket: FcmTicket::new(header.target_cid.get(), header.session_cid.get(), header.ticket.get()) })
}