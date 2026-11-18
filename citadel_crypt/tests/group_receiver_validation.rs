//! A group receiver checks everything a packet names before it records the packet, so a packet it
//! refuses never stops the genuine packet for the same sequence from being accepted, and a wave
//! that fails to decrypt is emptied for the genuine packets to fill again rather than dropped.
use bytes::BufMut;
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::scramble::crypt_splitter::{
    par_scramble_encrypt_group, GroupReceiver, GroupReceiverStatus, GroupSenderDevice,
};
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};
use citadel_types::proto::{ObjectId, TransferType};

type R = StackedRatchet;
const PSKS: &[&[u8]] = &[b"psk"];
const HDR: usize = 44;

fn pair() -> (R, R) {
    let opts = ConstructorOpts::new_vec_init(
        Some(EncryptionAlgorithm::AES_GCM_256 + KemAlgorithm::MlKem),
        SecurityLevel::Standard,
    );
    let mut a = <R as Ratchet>::Constructor::new_alice(opts.clone(), 99, 0).unwrap();
    let mut b =
        <R as Ratchet>::Constructor::new_bob(99, opts, a.stage0_alice().unwrap(), PSKS).unwrap();
    a.stage1_alice(b.stage0_bob().unwrap(), PSKS).unwrap();
    (a.finish().unwrap(), b.finish().unwrap())
}

/// A sender for 5000 bytes (several waves) and the receiver that pairs with it.
fn group() -> (GroupSenderDevice<HDR>, GroupReceiver, R) {
    let (alice, bob) = pair();
    let (aux_a, _aux_b) = pair();
    let data = vec![7u8; 5000];
    let tx = par_scramble_encrypt_group::<_, _, _, HDR>(
        &data[..],
        SecurityLevel::Standard,
        &alice,
        &aux_a,
        HDR,
        0,
        ObjectId::zero(),
        0,
        TransferType::FileTransfer,
        |_v, _b, _o, _c, buf| {
            for x in 0..HDR {
                buf.put_u8(x as u8)
            }
        },
    )
    .unwrap();
    let rx = GroupReceiver::new(tx.get_receiver_config().clone(), 0, 0);
    (tx, rx, bob)
}

/// Delivers every packet; `before_first` may first offer the receiver a forged packet for the first
/// sequence, which must be refused. Returns the last status.
fn deliver(before_first: impl Fn(&mut GroupReceiver, usize, u32, &R)) -> GroupReceiverStatus {
    let (mut tx, mut rx, bob) = group();
    let mut first = true;
    let mut last = GroupReceiverStatus::INSERT_SUCCESS;
    while let Some(p) = tx.get_next_packet() {
        if first {
            before_first(&mut rx, p.vector.true_sequence, p.vector.wave_id, &bob);
            first = false;
        }
        last = rx.on_packet_received(0, p.vector.true_sequence, p.vector.wave_id, &bob, p.payload);
        assert_ne!(
            last,
            GroupReceiverStatus::ALREADY_RECEIVED,
            "genuine packet refused"
        );
    }
    last
}

#[test]
fn the_group_completes() {
    assert!(matches!(
        deliver(|_, _, _, _| {}),
        GroupReceiverStatus::GROUP_COMPLETE(_)
    ));
}

#[test]
fn the_group_completes_after_an_oversized_packet_is_refused() {
    let status = deliver(|rx, seq, wave, bob| {
        let refused = rx.on_packet_received(0, seq, wave, bob, vec![0u8; 1 << 16]);
        assert_eq!(refused, GroupReceiverStatus::INVALID_PACKET);
    });
    assert!(matches!(status, GroupReceiverStatus::GROUP_COMPLETE(_)));
}

#[test]
fn the_group_completes_after_a_packet_naming_another_wave_is_refused() {
    let status = deliver(|rx, seq, wave, bob| {
        let refused = rx.on_packet_received(0, seq, wave + 1, bob, vec![0u8; 8]);
        assert_eq!(refused, GroupReceiverStatus::INVALID_PACKET);
    });
    assert!(matches!(status, GroupReceiverStatus::GROUP_COMPLETE(_)));
}

#[test]
fn a_wave_that_fails_to_decrypt_can_be_filled_again() {
    let (mut tx, mut rx, bob) = group();
    let mut packets = Vec::new();
    while let Some(p) = tx.get_next_packet() {
        packets.push((p.vector.true_sequence, p.vector.wave_id, p.payload.to_vec()));
    }
    let first_wave: Vec<_> = packets.iter().filter(|p| p.1 == 0).cloned().collect();
    assert!(first_wave.len() > 1, "the first wave has several packets");
    // A same-sized forgery takes the first packet's place, so the wave fails to decrypt.
    let (seq, wave, genuine) = &first_wave[0];
    let forged = vec![0u8; genuine.len()];
    assert_eq!(
        rx.on_packet_received(0, *seq, *wave, &bob, &forged),
        GroupReceiverStatus::INSERT_SUCCESS
    );
    let mut status = GroupReceiverStatus::INSERT_SUCCESS;
    for (seq, wave, payload) in &first_wave[1..] {
        status = rx.on_packet_received(0, *seq, *wave, &bob, payload);
    }
    assert_eq!(status, GroupReceiverStatus::CORRUPT_WAVE);
    // The genuine packets, sent again, complete the group.
    for (seq, wave, payload) in &packets {
        status = rx.on_packet_received(0, *seq, *wave, &bob, payload);
        assert_ne!(
            status,
            GroupReceiverStatus::ALREADY_RECEIVED,
            "resent packet refused"
        );
    }
    assert!(matches!(status, GroupReceiverStatus::GROUP_COMPLETE(_)));
}
