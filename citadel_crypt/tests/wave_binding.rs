//! A wave opens only in the transfer, group and position it was sealed for.
use bytes::BufMut;
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::scramble::crypt_splitter::{
    par_scramble_encrypt_group, GroupReceiver, GroupReceiverStatus, WaveBinding,
};
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};
use citadel_types::proto::{ObjectId, TransferType};

type R = StackedRatchet;
const PSKS: &[&[u8]] = &[b"psk"];
const HDR: usize = 44;
const LEN: usize = 20_000;
const BOUND: WaveBinding = WaveBinding::Bound;

fn pair() -> (R, R) {
    let opts = ConstructorOpts::new_vec_init(
        EncryptionAlgorithm::AES_GCM_256 + KemAlgorithm::MlKem,
        SecurityLevel::Standard,
    );
    let mut a = <R as Ratchet>::Constructor::new_alice(opts.clone(), 99, 0).unwrap();
    let mut b =
        <R as Ratchet>::Constructor::new_bob(99, opts, a.stage0_alice().unwrap(), PSKS).unwrap();
    a.stage1_alice(b.stage0_bob().unwrap(), PSKS).unwrap();
    (a.finish().unwrap(), b.finish().unwrap())
}

/// One packet as the receiver sees it: (true sequence, wave, payload).
type Packet = (usize, u32, Vec<u8>);

struct Sealed {
    packets: Vec<Packet>,
    receiver: GroupReceiver,
    per_wave: usize,
}

fn seal(
    alice: &R,
    fill: u8,
    object_id: u128,
    group_id: u64,
    sender: WaveBinding,
    receiver: WaveBinding,
) -> Sealed {
    let (aux, _) = pair();
    let mut tx = par_scramble_encrypt_group::<_, _, _, HDR>(
        vec![fill; LEN],
        SecurityLevel::Standard,
        alice,
        &aux,
        HDR,
        0,
        ObjectId(object_id),
        group_id,
        TransferType::FileTransfer,
        sender,
        |_v, _b, _o, _c, buf| {
            for x in 0..HDR {
                buf.put_u8(x as u8)
            }
        },
    )
    .unwrap();
    let cfg = tx.get_receiver_config().clone();
    assert!(
        cfg.number_of_full_waves >= 2,
        "two full waves to move between"
    );
    let mut packets = Vec::new();
    while let Some(p) = tx.get_next_packet() {
        packets.push((p.vector.true_sequence, p.vector.wave_id, p.payload.to_vec()));
    }
    packets.sort_by_key(|p| p.0);
    Sealed {
        packets,
        receiver: GroupReceiver::new(cfg.clone(), receiver, 0, 0),
        per_wave: cfg.max_packets_per_wave as usize,
    }
}

fn feed(rx: &mut GroupReceiver, bob: &R, group_id: u64, packets: &[Packet]) -> GroupReceiverStatus {
    let mut last = GroupReceiverStatus::INSERT_SUCCESS;
    for (seq, wave, payload) in packets {
        last = rx.on_packet_received(group_id, *seq, *wave, bob, payload);
        if last == GroupReceiverStatus::CORRUPT_WAVE {
            return last;
        }
    }
    last
}

#[test]
fn a_wave_from_another_transfer_is_refused() {
    let (alice, bob) = pair();
    let other = seal(&alice, 0xaa, 1, 10, BOUND, BOUND);
    let mut genuine = seal(&alice, 0xbb, 2, 11, BOUND, BOUND);
    let mixed: Vec<Packet> = other
        .packets
        .iter()
        .filter(|p| p.1 == 0)
        .chain(genuine.packets.iter().filter(|p| p.1 != 0))
        .cloned()
        .collect();
    let status = feed(&mut genuine.receiver, &bob, 11, &mixed);
    assert_eq!(status, GroupReceiverStatus::CORRUPT_WAVE);
}

#[test]
fn a_wave_moved_to_another_index_is_refused() {
    let (alice, bob) = pair();
    let mut sealed = seal(&alice, 0xcc, 3, 12, BOUND, BOUND);
    let per_wave = sealed.per_wave;
    let swapped: Vec<Packet> = sealed
        .packets
        .iter()
        .map(|(seq, wave, payload)| match wave {
            0 => (seq + per_wave, 1, payload.clone()),
            1 => (seq - per_wave, 0, payload.clone()),
            _ => (*seq, *wave, payload.clone()),
        })
        .collect();
    let status = feed(&mut sealed.receiver, &bob, 12, &swapped);
    assert_eq!(status, GroupReceiverStatus::CORRUPT_WAVE);
}

fn completes(sender: WaveBinding, receiver: WaveBinding) -> bool {
    let (alice, bob) = pair();
    let mut sealed = seal(&alice, 0xdd, 4, 13, sender, receiver);
    let packets = sealed.packets.clone();
    let status = feed(&mut sealed.receiver, &bob, 13, &packets);
    let complete = matches!(status, GroupReceiverStatus::GROUP_COMPLETE(_));
    if complete {
        assert!(sealed.receiver.finalize().iter().all(|b| *b == 0xdd));
    }
    complete
}

#[test]
fn an_untouched_transfer_completes() {
    assert!(completes(BOUND, BOUND));
}

#[test]
fn a_transfer_between_nodes_below_the_binding_completes() {
    assert!(completes(WaveBinding::Unbound, WaveBinding::Unbound));
}

#[test]
fn a_receiver_that_expects_bound_waves_refuses_unbound_ones() {
    assert!(!completes(WaveBinding::Unbound, BOUND));
}
