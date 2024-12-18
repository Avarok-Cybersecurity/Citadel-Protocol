use super::includes::*;
use crate::error::NetworkError;
use crate::proto::endpoint_crypto_accessor::EndpointCryptoAccessor;
use crate::proto::packet_processor::primary_group_packet::get_resp_target_cid_from_header;

/// This will handle an inbound group packet
#[cfg_attr(feature = "localhost-testing", tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err, fields(is_server = _session.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get())))]
pub fn process_udp_packet(
    _session: &CitadelSession,
    packet: HdpPacket,
    hr_version: u32,
    accessor: &EndpointCryptoAccessor,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let (header, payload, _, _) = packet.decompose();

    let res = accessor.borrow_hr(
        Some(hr_version),
        move |hr, state_container| -> PrimaryProcessorResult {
            let header = header.as_ref();
            if let Some((header, payload)) =
                super::super::validation::aead::validate_custom(hr, &header, payload)
            {
                let peer_cid = get_resp_target_cid_from_header(&header);
                let payload = SecBuffer::from(payload.as_ref());
                if state_container.forward_data_to_unordered_channel(peer_cid, payload) {
                    log::trace!(target: "citadel", "Successfully sent data to unordered channel");
                    PrimaryProcessorResult::Void
                } else {
                    PrimaryProcessorResult::EndSession(
                        "UDP subsystem should close since the receiving channel dropped",
                    )
                }
            } else {
                log::warn!(target: "citadel", "Unable to validate UDP packet");
                PrimaryProcessorResult::Void
            }
        },
    );

    match res {
        Ok(res) => Ok(res),
        Err(err) => {
            log::warn!(target: "citadel", "Unable to borrow HR: {:?}", err);
            Ok(PrimaryProcessorResult::Void)
        }
    }
}
