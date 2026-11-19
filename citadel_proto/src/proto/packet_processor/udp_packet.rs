//! UDP Packet Processor for Citadel Protocol
//!
//! This module handles the processing of UDP packets in the Citadel Protocol network.
//! It provides secure, unordered data transmission over UDP while maintaining the
//! protocol's security guarantees.
//!
//! # Features
//!
//! - Secure UDP packet processing
//! - Unordered data channel management
//! - Packet validation and authentication
//! - Channel state monitoring
//! - Automatic channel cleanup
//!
//! # Important Notes
//!
//! - Requires an established session
//! - All packets must be authenticated
//! - Handles unordered data transmission
//! - Automatically closes inactive channels
//! - Validates packet headers and payloads
//!
//! # Related Components
//!
//! - `EndpointCryptoAccessor`: Provides cryptographic operations
//! - `StateContainer`: Manages UDP channel state
//! - `SecBuffer`: Handles secure data buffering
//! - `HdpPacket`: Base packet structure

use super::includes::*;
use crate::error::NetworkError;
use crate::proto::endpoint_crypto_accessor::EndpointCryptoAccessor;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_processor::primary_group_packet::get_resp_target_cid_from_header;
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;

/// This will handle an inbound group packet
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = _session.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get()
    )
))]
pub fn process_udp_packet<R: Ratchet, T: PlatformOps>(
    _session: &CitadelSession<R, T>,
    packet: HdpPacket,
    hr_version: u32,
    accessor: &EndpointCryptoAccessor<R>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let (header, payload, _, _) = packet.decompose();
    let accessor_target = accessor.get_target_cid();

    let res = accessor.borrow_hr(
        Some(hr_version),
        move |hr, state_container| -> PrimaryProcessorResult {
            if let Some((peer_cid, payload)) =
                open_datagram(hr, accessor_target, header.as_ref(), payload)
            {
                let payload = SecBuffer::from(payload);
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
            log::warn!(target: "citadel", "Unable to borrow HR: {err:?}");
            Ok(PrimaryProcessorResult::Void)
        }
    }
}

/// Opens one datagram that arrived on the UDP channel of `channel_cid` under that channel's
/// ratchet, and names the virtual connection its payload belongs to.
///
/// The ratchet that opens it belongs to `channel_cid`, so that is the only connection it is
/// delivered to; a datagram whose header names a different endpoint is dropped.
pub(crate) fn open_datagram<R: Ratchet>(
    hr: &R,
    channel_cid: u64,
    header: &[u8],
    payload: BytesMut,
) -> Option<(u64, BytesMut)> {
    let (header, payload) = super::super::validation::aead::validate_custom(hr, &header, payload)?;
    let named = get_resp_target_cid_from_header(&header);
    if named != channel_cid {
        log::debug!(target: "citadel", "Dropping a UDP datagram for {named} that arrived on the channel of {channel_cid}");
        return None;
    }
    Some((named, payload))
}
