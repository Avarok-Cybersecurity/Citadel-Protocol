use super::includes::*;
use crate::hdp::hdp_packet_processor::primary_group_packet::{get_resp_target_cid_from_header, get_proper_hyper_ratchet};

/// This will handle an inbound group packet
pub fn process(session: &HdpSession, packet: HdpPacket, hr_version: u32, proxy_cid_info: Option<(u64, u64)>) -> PrimaryProcessorResult {
    let (header, payload, _, _) = packet.decompose();
    let ref cnac = session.cnac.get()?;
    let state_container = inner!(session.state_container);
    let ref hr = get_proper_hyper_ratchet(hr_version, cnac, &state_container, proxy_cid_info)?;

    let header = header.as_ref();
    let (header, payload) = super::super::validation::aead::validate_custom(hr, &header, payload)?;
    log::info!("Success validating hole-punch packet");
    let peer_cid = get_resp_target_cid_from_header(&header);
    state_container.hole_puncher_pipes.get(&peer_cid)?.send(payload).ok()?;
    log::info!("Success forwarding hole-punch packet to hole-puncher");

    PrimaryProcessorResult::Void
}
