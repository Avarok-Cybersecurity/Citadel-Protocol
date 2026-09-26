//! WASM Integration Tests — Cryptographic Primitives
//!
//! Verifies that credential creation, SecBuffer, and crypto parameter
//! composition work correctly on wasm32-unknown-unknown.

#![cfg(target_family = "wasm")]

use citadel_sdk::prelude::*;
use wasm_bindgen_test::*;

/// Verify transient credential creation works on WASM.
#[wasm_bindgen_test]
fn test_transient_credentials() {
    let creds = ProposedCredentials::transient("wasm-user-001");
    assert!(creds.username().contains("wasm-user-001"));
}

/// Verify SecBuffer can hold and retrieve data on WASM.
#[wasm_bindgen_test]
fn test_secbuffer_operations() {
    let data = b"secret payload for wasm";
    let buf = SecBuffer::from(&data[..]);
    assert_eq!(buf.as_ref(), data);
}

/// Verify SecBuffer from string works on WASM.
#[wasm_bindgen_test]
fn test_secbuffer_from_string() {
    let buf = SecBuffer::from("password123");
    assert_eq!(buf.len(), 11);
}

/// Verify all CryptoParameters combinations build successfully on WASM.
#[wasm_bindgen_test]
fn test_crypto_params_combinations() {
    let encryptions = [
        EncryptionAlgorithm::AES_GCM_256,
        EncryptionAlgorithm::ChaCha20Poly_1305,
        EncryptionAlgorithm::Ascon80pq,
    ];
    let kems = [KemAlgorithm::MlKem];
    let levels = [
        SecurityLevel::Standard,
        SecurityLevel::Reinforced,
        SecurityLevel::High,
        SecurityLevel::Ultra,
        SecurityLevel::Extreme,
    ];

    for enc in &encryptions {
        for kem in &kems {
            for level in &levels {
                let result = SessionSecuritySettingsBuilder::default()
                    .with_crypto_params(*enc + *kem)
                    .with_security_level(*level)
                    .build();
                assert!(result.is_ok(), "Failed for {enc:?} + {kem:?} @ {level:?}");
            }
        }
    }

    // MlKemHybrid requires a SigAlgorithm — test separately
    let result = SessionSecuritySettingsBuilder::default()
        .with_crypto_params(
            EncryptionAlgorithm::MlKemHybrid + KemAlgorithm::MlKem + SigAlgorithm::MlDsa65,
        )
        .build();
    assert!(result.is_ok(), "Failed for MlKemHybrid + MlKem + MlDsa65");
}

/// Verify ProposedCredentials::transient works with custom names on WASM.
#[wasm_bindgen_test]
fn test_transient_credentials_custom() {
    let creds = ProposedCredentials::transient("custom-user-42");
    assert!(creds.username().contains("custom-user-42"));
}

/// Verify the default SessionSecuritySettings are sound on WASM.
#[wasm_bindgen_test]
fn test_default_session_security() {
    let settings = SessionSecuritySettings::default();
    // Default should use Standard security level
    assert!(matches!(settings.security_level, SecurityLevel::Standard));
}

/// Verify MonoRatchet type alias is available on WASM (used for FCM).
#[wasm_bindgen_test]
fn test_mono_ratchet_availability() {
    // MonoRatchet is available via prelude — verify the type exists
    fn _assert_ratchet<R: Ratchet>() {}
    _assert_ratchet::<MonoRatchet>();
    _assert_ratchet::<StackedRatchet>();
}

/// Scrambling a source into groups is how a node sends any file. It ran each group on
/// `tokio::task::spawn_blocking`, which has no pool on wasm and panics, so a wasm node (a
/// Durable Object serving a RE-VFS pull) crashed on its first outbound file.
#[wasm_bindgen_test]
async fn a_source_scrambles_into_groups_that_reassemble_byte_for_byte() {
    // A node runs its tasks in a LocalSet (the scrambler spawns its streamer onto it).
    citadel_io::tokio::task::LocalSet::new()
        .run_until(scramble_and_reassemble())
        .await;
}

async fn scramble_and_reassemble() {
    use bytes::{BufMut, BytesMut};
    use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
    use citadel_crypt::packet_vector::PacketVector;
    use citadel_crypt::ratchets::entropy_bank::EntropyBank;
    use citadel_crypt::scramble::crypt_splitter::{GroupReceiver, GroupReceiverStatus};
    use citadel_crypt::scramble::streaming_crypt_scrambler::{
        scramble_encrypt_source, BytesSource,
    };
    use citadel_types::proto::{ObjectId, TransferType};

    const HEADER_LEN: usize = 52;
    fn header_inscribe(_: &PacketVector, _: &EntropyBank, _: ObjectId, _: u64, p: &mut BytesMut) {
        for x in 0..HEADER_LEN {
            p.put_u8(x as u8)
        }
    }

    fn pair(params: CryptoParameters) -> (StackedRatchet, StackedRatchet) {
        use citadel_pqcrypto::constructor_opts::ConstructorOpts;
        let opts = || ConstructorOpts::new_vec_init(Some(params), SecurityLevel::Standard);
        let psks: &[&[u8]] = &[b"psk"];
        let mut alice = <StackedRatchet as Ratchet>::Constructor::new_alice(opts(), 1, 0).unwrap();
        let mut bob = <StackedRatchet as Ratchet>::Constructor::new_bob(
            1,
            opts(),
            alice.stage0_alice().unwrap(),
            psks,
        )
        .expect("bob");
        alice.stage1_alice(bob.stage0_bob().unwrap(), psks).unwrap();
        (alice.finish().unwrap(), bob.finish().unwrap())
    }

    let params = KemAlgorithm::MlKem + EncryptionAlgorithm::AES_GCM_256;
    let (alice, bob) = pair(params);
    let (aux, _) = pair(params);
    let plaintext: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    let (tx, mut rx) = citadel_io::tokio::sync::mpsc::channel(1);
    let (_stop_tx, stop_rx) = citadel_io::tokio::sync::oneshot::channel();
    let (len, groups, _) = scramble_encrypt_source::<_, _, HEADER_LEN, _>(
        BytesSource::from(plaintext.clone()),
        Some(64 * 1024),
        ObjectId::zero(),
        tx,
        stop_rx,
        SecurityLevel::Standard,
        alice,
        aux,
        HEADER_LEN,
        bob.get_cid(),
        0,
        TransferType::FileTransfer,
        header_inscribe,
    )
    .expect("scramble_encrypt_source");
    assert_eq!((len, groups), (plaintext.len(), 4));

    let mut out = Vec::new();
    for _ in 0..groups {
        let mut device = rx.recv().await.expect("a group").expect("group scrambled");
        let config = device.get_receiver_config();
        let mut receiver = GroupReceiver::new(config.clone(), 0, 0);
        while let Some(packet) = device.get_next_packet() {
            let status = receiver.on_packet_received(
                config.group_id,
                packet.vector.true_sequence,
                packet.vector.wave_id,
                &bob,
                packet.payload,
            );
            if let GroupReceiverStatus::GROUP_COMPLETE(_) = status {
                out.extend_from_slice(receiver.finalize().as_slice());
                break;
            }
        }
    }
    assert_eq!(out, plaintext);
}
