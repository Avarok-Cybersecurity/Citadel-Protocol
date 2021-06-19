use hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use crate::external_services::fcm::fcm_packet_processor::{FcmProcessorResult, FcmPacketMaybeNeedsSending};
use crate::misc::AccountError;
use std::sync::Arc;
use fcm::Client;
use crate::external_services::fcm::fcm_instance::FCMInstance;
use zerocopy::LayoutVerified;
use crate::external_services::fcm::data_structures::FcmHeader;

pub fn process<Fcm: Ratchet>(client: &Arc<Client>, endpoint_crypto: &mut PeerSessionCrypto<Fcm>, truncate_vers: Option<u32>, header: LayoutVerified<&'a [u8], FcmHeader>) -> FcmProcessorResult {
    log::info!("FCM RECV TRUNCATE");
    let instance = FCMInstance::new(endpoint_crypto.fcm_keys.clone()?, client.clone());
    if let Some(truncate_vers) = truncate_vers {
        endpoint_crypto.deregister_oldest_hyper_ratchet(truncate_vers).map_err(|err| AccountError::Generic(err.to_string()))?;
        log::info!("[FCM] Successfully deregistered FcmRatchet v {} locally, sending TRUNCATE_ACK", truncate_vers);
    }

    let _ = endpoint_crypto.maybe_unlock(false)?; // unconditional unlock
    endpoint_crypto.post_alice_stage1_or_post_stage1_bob();

    let truncate_ack = crate::external_services::fcm::fcm_packet_crafter::craft_truncate_ack(endpoint_crypto.get_hyper_ratchet(None)?, header.object_id.get(), header.group_id.get(), header.session_cid.get(), header.ticket.get(), truncate_vers);


    FcmProcessorResult::RequiresSave(Some(FcmPacketMaybeNeedsSending::some(Some(instance), truncate_ack)))
}