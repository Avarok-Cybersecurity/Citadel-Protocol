use hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use crate::fcm::fcm_packet_processor::FcmProcessorResult;
use crate::misc::AccountError;

pub fn process<Fcm: Ratchet>(endpoint_crypto: &mut PeerSessionCrypto<Fcm>, truncate_vers: u32) -> FcmProcessorResult {
    log::info!("FCM RECV TRUNCATE");
    endpoint_crypto.deregister_oldest_hyper_ratchet(truncate_vers).map_err(|err| AccountError::Generic(err.to_string()))?;
    log::info!("[FCM] Successfully deregistered FcmRatchet v {} locally", truncate_vers);
    FcmProcessorResult::RequiresSave
}