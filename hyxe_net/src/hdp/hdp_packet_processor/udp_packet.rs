use super::includes::*;
use crate::hdp::endpoint_crypto_accessor::EndpointCryptoAccessor;
use crate::hdp::hdp_packet_processor::primary_group_packet::get_resp_target_cid_from_header;

/// This will handle an inbound group packet
pub fn process(_session: &HdpSession, packet: HdpPacket, hr_version: u32, accessor: &EndpointCryptoAccessor) -> PrimaryProcessorResult {
    let (header, payload, _, _) = packet.decompose();

    accessor.borrow_hr(Some(hr_version), move |hr, state_container| -> PrimaryProcessorResult {
        let header = header.as_ref();
        let (header, payload) = super::super::validation::aead::validate_custom(hr, &header, payload)?;
        let peer_cid = get_resp_target_cid_from_header(&header);
        let payload = SecBuffer::from(payload.as_ref());
        if state_container.forward_data_to_unordered_channel(peer_cid, payload) {
            log::info!("Successfully sent data to unordered channel");
            PrimaryProcessorResult::Void
        } else {
            PrimaryProcessorResult::EndSession("UDP subsystem should close since the receiving channel dropped")
        }
    })?
}
