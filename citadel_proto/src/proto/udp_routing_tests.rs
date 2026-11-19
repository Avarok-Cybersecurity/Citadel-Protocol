//! A datagram on a P2P UDP channel reaches only the virtual connection whose key opened it.
#![cfg(test)]

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::proto::packet::{packet_flags, packet_sizes, HdpHeader};
use crate::proto::packet_processor::udp_packet::open_datagram;
use crate::proto::udp_packet_tests::connected_pair;
use bytes::BytesMut;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::crypto::SecurityLevel;
use zerocopy::{U32, U64};

const A: u64 = 100;
const B: u64 = 200;
const C: u64 = 300;

/// A STREAM datagram with the given header CIDs, sealed under `ratchet`.
fn sealed_by_holder_of(ratchet: &StackedRatchet, session_cid: u64, target_cid: u64) -> BytesMut {
    let header = HdpHeader {
        protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
        cmd_primary: packet_flags::cmd::primary::UDP,
        cmd_aux: packet_flags::cmd::aux::udp::STREAM,
        algorithm: 0,
        security_level: SecurityLevel::Standard.value(),
        context_info: Default::default(),
        group: Default::default(),
        wave_id: Default::default(),
        session_cid: U64::new(session_cid),
        entropy_bank_version: U32::new(ratchet.version()),
        timestamp: Default::default(),
        target_cid: U64::new(target_cid),
    };
    let payload = b"call media";
    let capacity =
        packet_sizes::protected_packet_capacity(ratchet, SecurityLevel::Standard, payload.len())
            .unwrap();
    let mut packet = BytesMut::with_capacity(capacity);
    header.inscribe_into(&mut packet);
    packet.extend_from_slice(payload);
    ratchet
        .protect_message_packet(
            Some(SecurityLevel::Standard),
            HDP_HEADER_BYTE_LEN,
            &mut packet,
        )
        .unwrap();
    packet
}

fn received_on_channel_of(
    channel_cid: u64,
    ratchet: &StackedRatchet,
    mut packet: BytesMut,
) -> Option<(u64, BytesMut)> {
    let payload = packet.split_off(HDP_HEADER_BYTE_LEN);
    open_datagram(ratchet, channel_cid, &packet[..], payload)
}

#[test]
fn a_datagram_naming_another_peer_is_not_delivered_to_that_peer() {
    let (b_end, a_end) = connected_pair(SecurityLevel::Standard);
    let naming_c = sealed_by_holder_of(&b_end, C, A);
    assert_eq!(received_on_channel_of(B, &a_end, naming_c), None);
}

#[test]
fn a_datagram_from_the_channel_peer_is_delivered_to_it() {
    let (b_end, a_end) = connected_pair(SecurityLevel::Standard);
    let genuine = sealed_by_holder_of(&b_end, B, A);
    let (cid, payload) = received_on_channel_of(B, &a_end, genuine).expect("delivered");
    assert_eq!(cid, B);
    assert_eq!(&payload[..], b"call media");
}
