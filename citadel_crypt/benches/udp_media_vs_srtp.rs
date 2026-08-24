//! Criterion micro-benchmark: Citadel's UDP per-datagram crypto path vs SRTP (AEAD-AES-128-GCM).
//!
//! Citadel arm: `protect_message_packet(Some(Standard), 64, ..)` on a presized `[64 B header |
//! 1150 B payload]` `BytesMut` (the media-fragment shape at MTU 1280) and the matching in-place
//! `validate_message_packet_in_place_split` on the peer ratchet (a fresh packet per iteration —
//! the anti-replay container rejects re-validating one packet). AES-GCM-256 and ChaCha20-Poly1305.
//! SRTP arm: `webrtc_srtp::context::Context` `encrypt_rtp`/`decrypt_rtp` on a 12 B RTP header +
//! 1000 B payload. SRTP's replay window rejects re-used sequence numbers, so every iteration gets a
//! fresh, monotonically increasing sequence number (built in the untimed `iter_batched` setup).
//!
//! Run: `cargo bench -p citadel_crypt --bench udp_media_vs_srtp`

#[path = "common/mod.rs"]
mod common;

use bytes::{BufMut, Bytes, BytesMut};
use citadel_crypt::ratchets::Ratchet;
use citadel_types::crypto::{EncryptionAlgorithm, SecurityLevel};
use common::make_ratchets;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::cell::Cell;
use webrtc_srtp::context::Context;
use webrtc_srtp::protection_profile::ProtectionProfile;

/// Citadel UDP packet header length (`citadel_proto::constants::HDP_HEADER_BYTE_LEN`).
const CITADEL_HEADER_LEN: usize = 64;
/// Fixed RTP header (v2, no CSRC, no extension).
const RTP_HEADER_LEN: usize = 12;
/// Media fragment payload: fits one Citadel UDP datagram (live P2P QUIC datagram budget is
/// 1162 B total => ~1066 B payload at Standard; 1000 matches the udp_media_stream default).
const PAYLOAD_LEN: usize = 1000;
/// Spare capacity so the in-place AEAD seal (per-layer tag + nonce + PID trailer) never reallocates.
const SPARE: usize = 256;

const CITADEL_ALGOS: &[(&str, EncryptionAlgorithm)] = &[
    ("citadel/aes_gcm_256", EncryptionAlgorithm::AES_GCM_256),
    (
        "citadel/chacha20_poly1305",
        EncryptionAlgorithm::ChaCha20Poly_1305,
    ),
];

fn citadel_plaintext() -> BytesMut {
    let mut p = BytesMut::with_capacity(CITADEL_HEADER_LEN + PAYLOAD_LEN + SPARE);
    for x in 0..CITADEL_HEADER_LEN {
        p.put_u8(x as u8);
    }
    p.put_bytes(0xAB, PAYLOAD_LEN);
    p
}

/// `[12 B RTP header | payload]` with sequence number `seq` (SSRC fixed, PT 96).
fn rtp_plaintext(seq: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(RTP_HEADER_LEN + PAYLOAD_LEN);
    p.put_u8(0x80);
    p.put_u8(96);
    p.put_u16(seq);
    p.put_u32(u32::from(seq).wrapping_mul(960));
    p.put_u32(0x1234_5678);
    p.put_bytes(0xAB, PAYLOAD_LEN);
    p
}

fn srtp_context() -> Context {
    let key = [0x11u8; 16];
    let salt = [0x22u8; 12];
    Context::new(&key, &salt, ProtectionProfile::AeadAes128Gcm, None, None).unwrap()
}

fn bench_protect(c: &mut Criterion) {
    let sec = SecurityLevel::Standard;
    let mut group = c.benchmark_group("udp_protect");
    group.throughput(Throughput::Bytes(PAYLOAD_LEN as u64));
    for (name, enc) in CITADEL_ALGOS {
        let (alice, _bob) = make_ratchets(*enc, sec);
        let template = citadel_plaintext();
        group.bench_function(*name, |b| {
            b.iter_batched(
                || template.clone(),
                |mut pkt| {
                    alice
                        .protect_message_packet(Some(sec), CITADEL_HEADER_LEN, &mut pkt)
                        .unwrap();
                    black_box(pkt)
                },
                BatchSize::SmallInput,
            )
        });
    }
    {
        let mut ctx = srtp_context();
        let seq = Cell::new(0u16);
        group.bench_function("srtp/aead_aes_128_gcm", |b| {
            b.iter_batched(
                || {
                    let s = seq.get();
                    seq.set(s.wrapping_add(1));
                    rtp_plaintext(s)
                },
                |pkt| black_box(ctx.encrypt_rtp(&pkt).unwrap()),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_validate(c: &mut Criterion) {
    let sec = SecurityLevel::Standard;
    let mut group = c.benchmark_group("udp_validate");
    group.throughput(Throughput::Bytes(PAYLOAD_LEN as u64));
    for (name, enc) in CITADEL_ALGOS {
        let (alice, bob) = make_ratchets(*enc, sec);
        let template = citadel_plaintext();
        // Protect a FRESH packet per iteration (untimed setup): the receiver's anti-replay
        // container rejects a second validation of the same packet ID, so validating one
        // pre-protected packet repeatedly would fail with "Anti-replay-attack: invalid".
        group.bench_function(*name, |b| {
            b.iter_batched(
                || {
                    let mut p = template.clone();
                    alice
                        .protect_message_packet(Some(sec), CITADEL_HEADER_LEN, &mut p)
                        .unwrap();
                    let header = p.split_to(CITADEL_HEADER_LEN);
                    (header, p)
                },
                |(header, mut payload)| {
                    bob.validate_message_packet_in_place_split(
                        Some(sec),
                        &header[..],
                        &mut payload,
                    )
                    .unwrap();
                    black_box(payload)
                },
                BatchSize::SmallInput,
            )
        });
    }
    {
        let mut enc_ctx = srtp_context();
        let mut dec_ctx = srtp_context();
        let seq = Cell::new(0u16);
        group.bench_function("srtp/aead_aes_128_gcm", |b| {
            b.iter_batched(
                || {
                    let s = seq.get();
                    seq.set(s.wrapping_add(1));
                    enc_ctx.encrypt_rtp(&rtp_plaintext(s)).unwrap()
                },
                |pkt: Bytes| black_box(dec_ctx.decrypt_rtp(&pkt).unwrap()),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, bench_protect, bench_validate);
criterion_main!(benches);
