use hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use crate::fcm::fcm_packet_processor::FcmProcessorResult;

pub fn process<Fcm: Ratchet>(endpoint_crypto: &mut PeerSessionCrypto<Fcm>, truncate_vers: u32) -> FcmProcessorResult {
    log::info!("FCM RECV TRUNCATE ACK");
    let _ = endpoint_crypto.maybe_unlock(false)?; // unconditional unlock
    log::info!("[FCM] Adjacent node successfully deregistered ratchet v{}", truncate_vers);
    FcmProcessorResult::RequiresSave(None)
}