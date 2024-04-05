use super::includes::*;
use crate::error::NetworkError;
use crate::proto::packet_processor::primary_group_packet::{
    get_proper_hyper_ratchet, get_resp_target_cid_from_header,
};

/// This will handle an inbound group packet
#[cfg_attr(feature = "localhost-testing", tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err, fields(is_server = session.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get())))]
pub fn process_hole_punch(
    session: &HdpSession,
    packet: HdpPacket,
    hr_version: u32,
    proxy_cid_info: Option<(u64, u64)>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let (header, payload, _, _) = packet.decompose();
    let state_container = inner_state!(session.state_container);
    let hr = return_if_none!(
        get_proper_hyper_ratchet(hr_version, &state_container, proxy_cid_info),
        "Unable to get proper HR"
    );
    let header = header.as_ref();
    let (header, payload) = return_if_none!(
        super::super::validation::aead::validate_custom(&hr, &header, payload),
        "Unable to validate packet"
    );
    log::trace!(target: "citadel", "Success validating hole-punch packet");
    let peer_cid = get_resp_target_cid_from_header(&header);
    return_if_none!(
        return_if_none!(
            state_container.hole_puncher_pipes.get(&peer_cid),
            "Unable to get hole puncher pipe"
        )
        .send(payload.freeze())
        .ok(),
        "Unable to forward hole-punch packet through pipe"
    );
    log::trace!(target: "citadel", "Success forwarding hole-punch packet to hole-puncher");

    Ok(PrimaryProcessorResult::Void)
}
