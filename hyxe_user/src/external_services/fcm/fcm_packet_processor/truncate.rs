use hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;
use crate::external_services::fcm::fcm_packet_processor::{FcmProcessorResult, InstanceParameter};
use crate::misc::{AccountError, EmptyOptional};
use zerocopy::LayoutVerified;
use crate::external_services::fcm::data_structures::FcmHeader;

pub async fn process<Fcm: Ratchet>(svc_params: InstanceParameter<'_>, endpoint_crypto: &mut PeerSessionCrypto<Fcm>, truncate_vers: Option<u32>, header: LayoutVerified<&'_ [u8], FcmHeader>) -> Result<FcmProcessorResult, AccountError> {
    log::trace!(target: "lusna", "FCM RECV TRUNCATE");
    let mut instance = svc_params.create_instance(endpoint_crypto)?;
    if let Some(truncate_vers) = truncate_vers {
        endpoint_crypto.deregister_oldest_hyper_ratchet(truncate_vers).map_err(|err| AccountError::Generic(err.to_string()))?;
        log::trace!(target: "lusna", "[FCM] Successfully deregistered FcmRatchet v {} locally, sending TRUNCATE_ACK", truncate_vers);
    }

    let _ = endpoint_crypto.maybe_unlock(false).map_empty_err()?; // unconditional unlock
    endpoint_crypto.post_alice_stage1_or_post_stage1_bob();

    let truncate_ack = crate::external_services::fcm::fcm_packet_crafter::craft_truncate_ack(endpoint_crypto.get_hyper_ratchet(None).map_empty_err()?, header.object_id.get(), header.group_id.get(), header.session_cid.get(), header.ticket.get(), truncate_vers);

    instance.send(truncate_ack, header.target_cid.get(), header.session_cid.get()).await?;

    Ok(FcmProcessorResult::RequiresSave)
}