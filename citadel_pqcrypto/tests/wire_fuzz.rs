//! Bytes received from the counterpart of a key exchange, however malformed, are refused without
//! panicking and within a time bound: both transfers, every cipher's ciphertexts and protected
//! packets, and a serialized container.
mod support;

use bytes::BytesMut;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_pqcrypto::wire::{AliceToBobTransferParameters, BobToAliceTransferParameters};
use citadel_pqcrypto::{EncryptionAlgorithmExt, PostQuantumContainer};
use citadel_types::crypto::{CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SigAlgorithm};
use std::time::Duration;
use support::wire_fuzz::campaign;

const PSKS: &[&[u8]] = &[b"psk"];
const CASES: usize = 1_000;
const DEADLINE: Duration = Duration::from_secs(300);
const HEADER: &[u8] = b"header";

fn suites() -> Vec<CryptoParameters> {
    vec![
        KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::MlKem + EncryptionAlgorithm::ChaCha20Poly_1305 + SigAlgorithm::MlDsa65,
        KemAlgorithm::MlKem + EncryptionAlgorithm::Ascon80pq,
        KemAlgorithm::MlKem + EncryptionAlgorithm::MlKemHybrid + SigAlgorithm::MlDsa65,
        KemAlgorithm::MlKem1024Fips203 + EncryptionAlgorithm::AES_GCM_256,
    ]
}

fn opts(params: CryptoParameters) -> ConstructorOpts {
    ConstructorOpts::new_init(params)
}

fn pair(params: CryptoParameters) -> (PostQuantumContainer, PostQuantumContainer) {
    let mut alice = PostQuantumContainer::new_alice(opts(params)).unwrap();
    let bob = PostQuantumContainer::new_bob(
        opts(params),
        alice.generate_alice_to_bob_transfer().unwrap(),
        PSKS,
    )
    .unwrap();
    alice
        .alice_on_receive_ciphertext(bob.generate_bob_to_alice_transfer().unwrap(), PSKS)
        .unwrap();
    (alice, bob)
}

#[test]
fn received_alice_transfers_never_panic() {
    let seeds = suites()
        .into_iter()
        .map(|p| {
            let alice = PostQuantumContainer::new_alice(opts(p)).unwrap();
            bincode::serialize(&alice.generate_alice_to_bob_transfer().unwrap()).unwrap()
        })
        .collect();
    campaign("alice transfer", seeds, CASES, DEADLINE, |bytes| {
        if let Ok(tx) = bincode::deserialize::<AliceToBobTransferParameters>(bytes) {
            for params in suites() {
                let _ = PostQuantumContainer::new_bob(opts(params), tx.clone(), PSKS);
            }
        }
    });
}

#[test]
fn received_bob_transfers_never_panic() {
    let mut alices = Vec::new();
    let mut seeds = Vec::new();
    for params in suites() {
        let alice = PostQuantumContainer::new_alice(opts(params)).unwrap();
        let bob = PostQuantumContainer::new_bob(
            opts(params),
            alice.generate_alice_to_bob_transfer().unwrap(),
            PSKS,
        )
        .unwrap();
        seeds.push(bincode::serialize(&bob.generate_bob_to_alice_transfer().unwrap()).unwrap());
        alices.push(alice.serialize_to_vector().unwrap());
    }
    campaign("bob transfer", seeds, CASES, DEADLINE, move |bytes| {
        if let Ok(tx) = bincode::deserialize::<BobToAliceTransferParameters>(bytes) {
            for alice in &alices {
                let mut alice = PostQuantumContainer::deserialize_from_bytes(alice).unwrap();
                let _ = alice.alice_on_receive_ciphertext(tx.clone(), PSKS);
            }
        }
    });
}

#[test]
fn received_ciphertexts_never_panic() {
    for params in suites() {
        let (alice, bob) = pair(params);
        let nonce: Vec<u8> = (0..params.encryption_algorithm.nonce_len() as u8).collect();
        let mut packet = BytesMut::from(HEADER);
        packet.extend_from_slice(b"a protected payload");
        alice
            .protect_packet_in_place(HEADER.len(), &mut packet, &nonce)
            .unwrap();
        let seeds = vec![
            alice.encrypt(b"a short message", &nonce).unwrap(),
            alice.encrypt(vec![7u8; 300], &nonce).unwrap(),
            packet[HEADER.len()..].to_vec(),
            alice.local_encrypt(b"local", &nonce).unwrap(),
        ];
        campaign("ciphertext", seeds, CASES, DEADLINE, move |bytes| {
            let _ = bob.decrypt(bytes, &nonce);
            let _ = alice.local_decrypt(bytes, &nonce);
            let mut buf = BytesMut::from(bytes);
            let _ = bob.validate_packet_in_place(HEADER, &mut buf, &nonce);
            let mut buf = BytesMut::from(bytes);
            let _ = bob.decrypt_in_place(&mut buf, HEADER, &nonce);
        });
    }
}

#[test]
fn serialized_containers_never_panic() {
    let seeds = suites()
        .into_iter()
        .map(|p| pair(p).1.serialize_to_vector().unwrap())
        .collect();
    campaign("container", seeds, CASES, DEADLINE, |bytes| {
        if let Ok(container) = PostQuantumContainer::deserialize_from_bytes(bytes) {
            let _ = container.decrypt(vec![0u8; 64], [0u8; 32]);
        }
    });
}
