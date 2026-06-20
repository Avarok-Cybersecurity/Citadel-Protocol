//! Criterion micro-benchmarks for the Citadel per-message and per-wave crypto hot paths.
//!
//! Establishes the Phase-0 baseline for the optimization sweep:
//! - `protect_message_packet` / `validate_message_packet` — the per-message AEAD+ratchet path
//!   (AES-GCM, ChaCha20-Poly1305, Ascon-80pq), which dominates messaging throughput.
//! - `par_scramble_encrypt_group` — the per-wave file-transfer encrypt path, across payload sizes.
//!
//! Run: `cargo bench -p citadel_crypt --bench crypto_hot_path`

use bytes::{BufMut, BytesMut};
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::scramble::crypt_splitter::par_scramble_encrypt_group;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::{CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SecurityLevel};
use citadel_types::proto::{ObjectId, TransferType};
use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

const HEADER_LEN: usize = 50;
const MSG_LEN: usize = 256;

fn psks() -> Vec<Vec<u8>> {
    vec![b"Hello".to_vec(), b"World".to_vec()]
}

/// Build a connected (alice, bob) ratchet pair for `enc`/MlKem at `sec`.
fn make_ratchets(enc: EncryptionAlgorithm, sec: SecurityLevel) -> (StackedRatchet, StackedRatchet) {
    let params: CryptoParameters = (KemAlgorithm::MlKem + enc).into();
    let params = Some(params);
    let psks = psks();

    let mut alice = <StackedRatchet as Ratchet>::Constructor::new_alice(
        ConstructorOpts::new_vec_init(params, sec),
        99,
        0,
    )
    .unwrap();
    let transfer = alice.stage0_alice().unwrap();
    let mut bob = <StackedRatchet as Ratchet>::Constructor::new_bob(
        99,
        ConstructorOpts::new_vec_init(params, sec),
        transfer,
        &psks,
    )
    .unwrap();
    let transfer = bob.stage0_bob().unwrap();
    alice.stage1_alice(transfer, &psks).unwrap();
    (alice.finish().unwrap(), bob.finish().unwrap())
}

/// `[header | plaintext]` with generous capacity so the in-place AEAD seal never reallocates
/// (we want to measure crypto, not allocator).
fn plaintext_packet() -> BytesMut {
    let mut p = BytesMut::with_capacity(HEADER_LEN + MSG_LEN + 256);
    for x in 0..HEADER_LEN {
        p.put_u8(x as u8);
    }
    p.put_bytes(0xAB, MSG_LEN);
    p
}

const ALGOS: &[(&str, EncryptionAlgorithm)] = &[
    ("aes_gcm_256", EncryptionAlgorithm::AES_GCM_256),
    ("chacha20_poly1305", EncryptionAlgorithm::ChaCha20Poly_1305),
    ("ascon80pq", EncryptionAlgorithm::Ascon80pq),
];

fn bench_protect(c: &mut Criterion) {
    let sec = SecurityLevel::Standard;
    let mut group = c.benchmark_group("protect_message_packet");
    group.throughput(Throughput::Bytes(MSG_LEN as u64));
    for (name, enc) in ALGOS {
        let (alice, _bob) = make_ratchets(*enc, sec);
        let template = plaintext_packet();
        group.bench_function(*name, |b| {
            b.iter_batched(
                || template.clone(),
                |mut pkt| {
                    alice
                        .protect_message_packet(Some(sec), HEADER_LEN, &mut pkt)
                        .unwrap();
                    black_box(pkt)
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_validate(c: &mut Criterion) {
    let sec = SecurityLevel::Standard;
    let mut group = c.benchmark_group("validate_message_packet");
    group.throughput(Throughput::Bytes(MSG_LEN as u64));
    for (name, enc) in ALGOS {
        let (alice, bob) = make_ratchets(*enc, sec);
        let mut protected = plaintext_packet();
        alice
            .protect_message_packet(Some(sec), HEADER_LEN, &mut protected)
            .unwrap();
        group.bench_function(*name, |b| {
            b.iter_batched(
                || {
                    let mut p = protected.clone();
                    let header = p.split_to(HEADER_LEN);
                    (header, p)
                },
                |(header, mut payload)| {
                    bob.validate_message_packet(Some(sec), &header[..], &mut payload)
                        .unwrap();
                    black_box(payload)
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_scramble(c: &mut Criterion) {
    let sec = SecurityLevel::Standard;
    let (alice, _bob) = make_ratchets(EncryptionAlgorithm::AES_GCM_256, sec);
    let mut group = c.benchmark_group("scramble_encrypt_group/aes_gcm_256");
    for size in [16 * 1024usize, 256 * 1024, 1024 * 1024] {
        let data = vec![0xCDu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let dev = par_scramble_encrypt_group::<_, _, _, HEADER_LEN>(
                    &data[..],
                    sec,
                    &alice,
                    &alice,
                    HEADER_LEN,
                    0,
                    ObjectId::zero(),
                    0,
                    TransferType::FileTransfer,
                    |_v, _e, _o, _c, buf: &mut BytesMut| {
                        for x in 0..HEADER_LEN {
                            buf.put_u8(x as u8);
                        }
                    },
                )
                .unwrap();
                black_box(dev)
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_protect, bench_validate, bench_scramble);
criterion_main!(benches);
