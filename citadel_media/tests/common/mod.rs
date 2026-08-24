#![allow(dead_code)]
use bytes::Bytes;
use citadel_media::{
    FrameFlags, FrameHeader, MediaConfig, MediaFrame, MediaInstant, TrackId, TrackKind,
};

// Test-only baseline config (PCND: production callers construct explicitly).
pub const CFG: MediaConfig = MediaConfig {
    max_fragment_payload: 100,
    max_frame_bytes: 10_000,
    max_reorder_window: 8,
    jitter_depth_micros: 20_000,
    max_pending_frames: 4,
};

pub const T0: MediaInstant = MediaInstant::from_micros(1_000_000);

pub fn at(offset_micros: u64) -> MediaInstant {
    T0.saturating_add_micros(offset_micros)
}

pub fn frame(track: u8, seq: u32, flags: FrameFlags) -> MediaFrame {
    MediaFrame {
        header: FrameHeader {
            track: TrackId(track),
            kind: TrackKind::Audio,
            sequence: seq,
            timestamp: seq.wrapping_mul(960),
            flags,
        },
        payload: Bytes::from(vec![seq as u8; 4]),
    }
}

pub fn payload(len: usize) -> Bytes {
    Bytes::from((0..len).map(|i| (i % 251) as u8).collect::<Vec<u8>>())
}

/// Deterministic LCG (Numerical Recipes constants) for reproducible shuffles/loss.
#[derive(Debug, Clone)]
pub struct Lcg(u64);

impl Lcg {
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u32() as usize) % n
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }

    /// Keeps each item with probability `(100 - loss_percent)%`.
    pub fn apply_loss<T>(&mut self, items: Vec<T>, loss_percent: usize) -> Vec<T> {
        items
            .into_iter()
            .filter(|_| self.below(100) >= loss_percent)
            .collect()
    }
}
