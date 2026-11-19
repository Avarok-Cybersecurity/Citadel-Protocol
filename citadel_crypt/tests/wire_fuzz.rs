//! Bytes received from the counterpart, however malformed, are refused or handled without
//! panicking and within a time bound: entropy banks, both ratchets' key-exchange transfers, group
//! receiver configurations and the packets of a group, and protected message packets.
mod support;

use bytes::{BufMut, BytesMut};
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::packet_vector::{generate_packet_coordinates_inv, generate_packet_vector};
use citadel_crypt::ratchets::entropy_bank::EntropyBank;
use citadel_crypt::ratchets::mono::{MonoAliceToBobTransfer, MonoBobToAliceTransfer, MonoRatchet};
use citadel_crypt::ratchets::stacked::constructor::{AliceToBobTransfer, BobToAliceTransfer};
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::scramble::crypt_splitter::{
    par_scramble_encrypt_group, GroupReceiver, GroupReceiverConfig,
};
use citadel_crypt::scramble::wave_binding::WaveBinding;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::{
    CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SecurityLevel, SigAlgorithm,
};
use citadel_types::proto::{ObjectId, TransferType};
use std::time::Duration;
use support::wire_fuzz::{campaign, Rng};

const PSKS: &[&[u8]] = &[b"psk"];
const CASES: usize = 500;
const DEADLINE: Duration = Duration::from_secs(300);
const HDR: usize = 44;

type Stacked = <StackedRatchet as Ratchet>::Constructor;
type Mono = <MonoRatchet as Ratchet>::Constructor;

fn suites() -> [CryptoParameters; 2] {
    [
        KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::MlKem + EncryptionAlgorithm::MlKemHybrid + SigAlgorithm::MlDsa65,
    ]
}

fn stacked_opts(params: CryptoParameters) -> Vec<ConstructorOpts> {
    ConstructorOpts::new_vec_init(Some(params), SecurityLevel::Standard)
}

fn stacked_pair(params: CryptoParameters) -> (StackedRatchet, StackedRatchet) {
    let mut a = Stacked::new_alice(stacked_opts(params), 9, 0).unwrap();
    let mut b = Stacked::new_bob(9, stacked_opts(params), a.stage0_alice().unwrap(), PSKS).unwrap();
    a.stage1_alice(b.stage0_bob().unwrap(), PSKS).unwrap();
    (a.finish().unwrap(), b.finish().unwrap())
}

#[test]
fn received_entropy_banks_never_panic() {
    let seeds = vec![EntropyBank::new(1, 0, EncryptionAlgorithm::AES_GCM_256)
        .unwrap()
        .serialize_to_vec()
        .unwrap()];
    campaign("entropy bank", seeds, 4 * CASES, DEADLINE, |bytes| {
        if let Ok(bank) = EntropyBank::deserialize_from(bytes) {
            for sequence in [0, 1, 13, 14, 1000, usize::MAX / 2] {
                let v = generate_packet_vector(sequence, 0, &bank);
                let _ =
                    generate_packet_coordinates_inv(v.wave_id, v.local_port, v.remote_port, &bank);
            }
        }
    });
}

#[test]
fn received_stacked_transfers_never_panic() {
    for params in suites() {
        let alice = Stacked::new_alice(stacked_opts(params), 9, 0).unwrap();
        let to_bob = alice.stage0_alice().unwrap();
        let to_bob_bytes = bincode::serialize(&to_bob).unwrap();
        let mut bob = Stacked::new_bob(9, stacked_opts(params), to_bob, PSKS).unwrap();
        let to_alice_bytes = bincode::serialize(&bob.stage0_bob().unwrap()).unwrap();
        let alice_bytes = bincode::serialize(&alice).unwrap();
        campaign(
            "stacked to bob",
            vec![to_bob_bytes],
            CASES,
            DEADLINE,
            move |bytes| {
                if let Ok(tx) = bincode::deserialize::<AliceToBobTransfer>(bytes) {
                    if let Some(mut bob) = Stacked::new_bob(9, stacked_opts(params), tx, PSKS) {
                        let _ = bob.stage0_bob();
                    }
                }
            },
        );
        campaign(
            "stacked to alice",
            vec![to_alice_bytes],
            CASES,
            DEADLINE,
            move |bytes| {
                if let Ok(tx) = bincode::deserialize::<BobToAliceTransfer>(bytes) {
                    let mut alice: Stacked = bincode::deserialize(&alice_bytes).unwrap();
                    if alice.stage1_alice(tx, PSKS).is_ok() {
                        let _ = alice.finish();
                    }
                }
            },
        );
    }
}

#[test]
fn received_mono_transfers_never_panic() {
    for params in suites() {
        let opts = vec![ConstructorOpts::new_init(Some(params))];
        let alice = Mono::new_alice(opts.clone(), 9, 0).unwrap();
        let to_bob = alice.stage0_alice().unwrap();
        let to_bob_bytes = bincode::serialize(&to_bob).unwrap();
        let mut bob = <Mono as EndpointRatchetConstructor<MonoRatchet>>::new_bob(
            9,
            opts.clone(),
            to_bob,
            PSKS,
        )
        .unwrap();
        let to_alice_bytes = bincode::serialize(&bob.stage0_bob().unwrap()).unwrap();
        let alice_bytes = bincode::serialize(&alice).unwrap();
        let bob_opts = opts.clone();
        campaign(
            "mono to bob",
            vec![to_bob_bytes],
            CASES,
            DEADLINE,
            move |bytes| {
                if let Ok(tx) = bincode::deserialize::<MonoAliceToBobTransfer>(bytes) {
                    if let Some(mut bob) =
                        <Mono as EndpointRatchetConstructor<MonoRatchet>>::new_bob(
                            9,
                            bob_opts.clone(),
                            tx,
                            PSKS,
                        )
                    {
                        let _ = bob.stage0_bob();
                    }
                }
            },
        );
        campaign(
            "mono to alice",
            vec![to_alice_bytes],
            CASES,
            DEADLINE,
            move |bytes| {
                if let Ok(tx) = bincode::deserialize::<MonoBobToAliceTransfer>(bytes) {
                    let mut alice: Mono = bincode::deserialize(&alice_bytes).unwrap();
                    let _ = alice.stage1_alice(tx, PSKS);
                }
            },
        );
    }
}

#[test]
fn received_group_packets_never_panic() {
    let (alice, bob) = stacked_pair(suites()[0]);
    let (aux, _) = stacked_pair(suites()[0]);
    let mut tx = par_scramble_encrypt_group::<_, _, _, HDR>(
        &vec![3u8; 5000][..],
        SecurityLevel::Standard,
        &alice,
        &aux,
        HDR,
        0,
        ObjectId::zero(),
        0,
        TransferType::FileTransfer,
        WaveBinding::Bound,
        |_v, _b, _o, _c, buf| buf.put_bytes(0, HDR),
    )
    .unwrap();
    let config = tx.get_receiver_config().clone();
    let config_bytes = bincode::serialize(&config).unwrap();
    let mut packets = Vec::new();
    while let Some(p) = tx.get_next_packet() {
        packets.push((p.vector.true_sequence, p.vector.wave_id, p.payload.to_vec()));
    }
    campaign(
        "receiver config",
        vec![config_bytes],
        4 * CASES,
        DEADLINE,
        |bytes| {
            if let Ok(cfg) = bincode::deserialize::<GroupReceiverConfig>(bytes) {
                if cfg.validate().is_ok() {
                    let _ = GroupReceiver::new(cfg, WaveBinding::Bound, 0, 0);
                }
            }
        },
    );
    let seeds = packets.iter().map(|p| p.2.clone()).collect();
    campaign("group packets", seeds, 4 * CASES, DEADLINE, move |bytes| {
        // The bytes choose which genuine packets precede the forged one and what it claims to be.
        let mut rng = Rng::new(bytes.iter().fold(0u64, |h, b| h.rotate_left(5) ^ *b as u64));
        let mut rx = GroupReceiver::new(config.clone(), WaveBinding::Bound, 0, 0);
        for (seq, wave, payload) in packets.iter().take(rng.below(packets.len() + 1)) {
            let _ = rx.on_packet_received(0, *seq, *wave, &bob, payload);
        }
        let seq = [
            rng.below(packets.len() + 2),
            usize::MAX,
            rng.next_u64() as usize,
        ][rng.below(3)];
        let wave = [rng.below(4) as u32, u32::MAX][rng.below(2)];
        let _ = rx.on_packet_received(0, seq, wave, &bob, bytes);
        let _ = rx.get_missing_waves();
    });
}

#[test]
fn received_message_packets_never_panic() {
    for params in suites() {
        let (alice, bob) = stacked_pair(params);
        let mut packet = BytesMut::new();
        packet.put_bytes(1, HDR);
        packet.put_slice(b"a message for bob");
        alice
            .protect_message_packet(Some(SecurityLevel::Standard), HDR, &mut packet)
            .unwrap();
        let seeds = vec![packet.to_vec(), alice.encrypt(b"contents").unwrap()];
        campaign("message packet", seeds, CASES, DEADLINE, move |bytes| {
            if bytes.len() >= HDR {
                let (header, payload) = bytes.split_at(HDR);
                let mut payload = BytesMut::from(payload);
                let _ = bob.validate_message_packet(
                    Some(SecurityLevel::Standard),
                    header,
                    &mut payload,
                );
                let _ = bob.validate_message_packet(
                    Some(SecurityLevel::Custom(200)),
                    header,
                    &mut payload,
                );
            }
            let _ = bob.decrypt(bytes);
            let _ = bob.local_decrypt(bytes.to_vec(), SecurityLevel::Standard);
        });
    }
}
