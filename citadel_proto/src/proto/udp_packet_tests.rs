//! Unit tests for the UDP datagram sealing path (`packet_crafter::udp`) and its sizing SSOT.
#![cfg(test)]

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::proto::packet::{packet_flags, packet_sizes};
use crate::proto::packet_crafter::udp::craft_udp_packet;
use bytes::BytesMut;
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::{CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SecurityLevel};

fn connected_pair(max_level: SecurityLevel) -> (StackedRatchet, StackedRatchet) {
    let params: CryptoParameters = KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256;
    let params = Some(params);
    let psks = vec![b"udp".to_vec(), b"test".to_vec()];
    let mut alice = <StackedRatchet as Ratchet>::Constructor::new_alice(
        ConstructorOpts::new_vec_init(params, max_level),
        7,
        0,
    )
    .unwrap();
    let transfer = alice.stage0_alice().unwrap();
    let mut bob = <StackedRatchet as Ratchet>::Constructor::new_bob(
        7,
        ConstructorOpts::new_vec_init(params, max_level),
        transfer,
        &psks,
    )
    .unwrap();
    let transfer = bob.stage0_bob().unwrap();
    alice.stage1_alice(transfer, &psks).unwrap();
    (alice.finish().unwrap(), bob.finish().unwrap())
}

#[test]
fn capacity_helper_matches_actual_sealed_length() {
    let (alice, _) = connected_pair(SecurityLevel::High);
    for (level, layers) in [
        (SecurityLevel::Standard, 1),
        (SecurityLevel::Reinforced, 2),
        (SecurityLevel::High, 3),
    ] {
        let payload = BytesMut::from(&[0xABu8; 1100][..]);
        let expected =
            packet_sizes::protected_packet_capacity(&alice, level, payload.len()).unwrap();
        assert_eq!(
            expected,
            HDP_HEADER_BYTE_LEN + 1100 + layers * packet_sizes::MESSAGE_PACKET_PER_LAYER_OVERHEAD
        );
        let packet = craft_udp_packet(
            &alice,
            packet_flags::cmd::aux::udp::STREAM,
            payload,
            7,
            level,
        )
        .unwrap();
        assert_eq!(packet.len(), expected, "sealed length at {level:?}");
        assert_eq!(
            packet.capacity(),
            expected,
            "no realloc during seal at {level:?}"
        );
    }
}

#[test]
fn unsupported_level_is_an_error_not_a_panic() {
    let (alice, _) = connected_pair(SecurityLevel::Standard);
    let payload = BytesMut::from(&[1u8; 16][..]);
    let res = craft_udp_packet(
        &alice,
        packet_flags::cmd::aux::udp::STREAM,
        payload,
        7,
        SecurityLevel::Reinforced,
    );
    assert!(res.is_err());
}

#[test]
fn sealed_packet_round_trips_through_peer_ratchet() {
    let (alice, bob) = connected_pair(SecurityLevel::Reinforced);
    let payload = BytesMut::from(&b"media fragment"[..]);
    let mut packet = craft_udp_packet(
        &alice,
        packet_flags::cmd::aux::udp::STREAM,
        payload,
        7,
        SecurityLevel::Reinforced,
    )
    .unwrap();
    let header = packet.split_to(HDP_HEADER_BYTE_LEN);
    bob.validate_message_packet_in_place_split(
        Some(SecurityLevel::Reinforced),
        &header,
        &mut packet,
    )
    .unwrap();
    assert_eq!(&packet[..], b"media fragment");
}
