use hyxe_crypt::endpoint_crypto_container::{PeerSessionCrypto, KemTransferStatus, EndpointRatchetConstructor};
use hyxe_crypt::hyper_ratchet::Ratchet;
use crate::external_services::fcm::data_structures::{FcmHeader, FcmTicket};
use zerocopy::LayoutVerified;
use crate::external_services::fcm::fcm_packet_processor::{FcmProcessorResult, FcmResult, InstanceParameter};
use hyxe_crypt::hyper_ratchet::constructor::AliceToBobTransferType;
use crate::misc::AccountError;
use hyxe_crypt::fcm::fcm_ratchet::FcmAliceToBobTransfer;

pub async fn process<'a, Fcm: Ratchet>(svc_params: InstanceParameter<'a>, endpoint_crypto: &'a mut PeerSessionCrypto<Fcm>, ratchet: Fcm, header: LayoutVerified<&'a [u8], FcmHeader>, alice_to_bob_transfer: Option<FcmAliceToBobTransfer<'a>>, message: &'a [u8]) -> Result<FcmProcessorResult, AccountError> {
    log::info!("FCM RECV GROUP_HEADER");
    let mut instance = svc_params.create_instance(endpoint_crypto)?;
    // at this point, the packet was verified to be valid. Calculate return packet, send it via fcm to target. Finally, return the message
    let local_cid = header.target_cid.get();

    let kem_transfer_status = if let Some(transfer) = alice_to_bob_transfer {
        let opts = ratchet.get_next_constructor_opts();
        let constructor = Fcm::Constructor::new_bob(local_cid, header.ratchet_version.get().wrapping_add(1), opts,AliceToBobTransferType::Fcm(transfer)).ok_or_else(|| AccountError::msg("FCM new_bob error"))?;
        endpoint_crypto.update_sync_safe(constructor, false, local_cid).map_err(|_| AccountError::IoError("Error while updating crypt container".to_string()))?
    } else {
        // no update needed since one is probably already concurrently happening
        KemTransferStatus::Empty
    };

    let packet = super::super::fcm_packet_crafter::craft_group_header_ack(&ratchet, header.object_id.get(), header.group_id.get(), header.session_cid.get(), header.ticket.get(), kem_transfer_status);

    let ticket = FcmTicket::new(header.session_cid.get(), header.target_cid.get(), header.ticket.get());

    instance.send(packet, local_cid, header.session_cid.get()).await?;

    log::info!("SUBROUTINE COMPLETE: PROCESS GROUP_HEADER");
    // now that we sent the response to FCM, the next step is to return with the original message
    Ok(FcmProcessorResult::Value(FcmResult::GroupHeader { ticket, message: message.to_vec() }))
}