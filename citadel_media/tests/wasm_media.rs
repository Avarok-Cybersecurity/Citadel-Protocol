#![cfg(target_family = "wasm")]

use bytes::Bytes;
use citadel_media::{
    FrameFlags, JitterBuffer, MediaConfig, MediaInstant, Packetizer, PopResult, ReassembleOutcome,
    Reassembler, TrackId, TrackKind,
};
use wasm_bindgen_test::wasm_bindgen_test;

// Test-only config (PCND: production callers construct explicitly).
const CFG: MediaConfig = MediaConfig {
    max_fragment_payload: 100,
    max_frame_bytes: 10_000,
    max_reorder_window: 8,
    jitter_depth_micros: 20_000,
    max_pending_frames: 64,
};

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
}

#[wasm_bindgen_test]
fn packetize_shuffle_reassemble_jitter() {
    let mut p = Packetizer::new(CFG).unwrap();
    let mut datagrams = Vec::new();
    for seq in 0..10u32 {
        let payload = Bytes::from(vec![seq as u8; 250]);
        for f in p
            .packetize(
                TrackId(0),
                TrackKind::Audio,
                seq * 960,
                FrameFlags::NONE,
                payload,
            )
            .unwrap()
        {
            let mut d = f.header.to_vec();
            d.extend_from_slice(&f.payload);
            datagrams.push(d);
        }
    }
    let mut rng = Lcg(99);
    for i in (1..datagrams.len()).rev() {
        let j = rng.next() as usize % (i + 1);
        datagrams.swap(i, j);
    }
    // Drop every fragment of frame 4 so the jitter buffer must skip a gap.
    datagrams.retain(|d| d[7] != 4);

    let mut r = Reassembler::new(CFG).unwrap();
    let mut j = JitterBuffer::new(CFG).unwrap();
    let t0 = MediaInstant::from_micros(0);
    for d in &datagrams {
        if let ReassembleOutcome::Complete(frame) = r.push(d, t0) {
            j.push(frame, t0);
        }
    }
    let mut delivered = Vec::new();
    let mut gaps = Vec::new();
    let later = t0.saturating_add_micros(CFG.jitter_depth_micros);
    loop {
        match j.pop_ready(later) {
            PopResult::Frame(f) => delivered.push(f.header.sequence),
            PopResult::Gap {
                missing_from,
                missing_to,
                next,
                ..
            } => {
                gaps.push((missing_from, missing_to));
                delivered.push(next.header.sequence);
            }
            PopResult::NotReady => break,
        }
    }
    assert_eq!(delivered, vec![0, 1, 2, 3, 5, 6, 7, 8, 9]);
    assert_eq!(gaps, vec![(4, 4)]);
}
