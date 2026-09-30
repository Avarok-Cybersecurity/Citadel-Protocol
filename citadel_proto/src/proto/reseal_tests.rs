//! A journaled message re-sent after its route ended must be accepted by the receiver however far
//! the receiver's anti-replay window has moved since it was first sealed (see
//! `peer::direct_journal`).
#![cfg(test)]

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::proto::packet::HdpHeader;
use crate::proto::packet_crafter::group::{reseal, seal};
use crate::proto::udp_packet_tests::connected_pair;
use crate::proto::validation::aead::validate_custom;
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;
use citadel_pqcrypto::replay_attack_container::HISTORY_LEN;
use citadel_types::crypto::SecurityLevel;
use zerocopy::FromZeroes;

const LEVEL: SecurityLevel = SecurityLevel::Standard;

fn plaintext(ratchet: &impl Ratchet, body: &[u8]) -> BytesMut {
    let mut header = HdpHeader::new_zeroed();
    header.security_level = LEVEL.value();
    header.session_cid.set(ratchet.get_cid());
    let mut packet = BytesMut::new();
    header.inscribe_into(&mut packet);
    packet.extend_from_slice(body);
    packet
}

/// Whether `receiver` accepts `packet`, and with what body.
fn accept(receiver: &impl Ratchet, mut packet: BytesMut) -> Option<Vec<u8>> {
    let header = packet.split_to(HDP_HEADER_BYTE_LEN);
    validate_custom(receiver, &header, packet).map(|(_, body)| body.to_vec())
}

#[test]
fn a_resent_message_is_accepted_after_the_replay_window_moved_past_it() {
    let (sender, receiver) = connected_pair(LEVEL);
    let lost = plaintext(&sender, b"the message the dead route lost");
    let original = seal(&sender, LEVEL, lost.clone()).unwrap();

    // The receiver goes on accepting the sender's later traffic, more than a window's worth.
    let mut newest = None;
    for _ in 0..=HISTORY_LEN {
        newest = Some(seal(&sender, LEVEL, plaintext(&sender, b"later")).unwrap());
    }
    assert!(accept(&receiver, newest.unwrap()).is_some());

    // The original ciphertext is now older than the window: refused as a replay.
    assert!(accept(&receiver, original).is_none());

    // Sealed again, the same message is accepted, byte for byte.
    let resent = reseal(&sender, 1, LEVEL, &lost).unwrap();
    assert_eq!(
        accept(&receiver, resent).as_deref(),
        Some(&b"the message the dead route lost"[..])
    );
}
