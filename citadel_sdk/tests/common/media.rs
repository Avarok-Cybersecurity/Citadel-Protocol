//! Shared helpers for the UDP media integration tests.
#![allow(dead_code)]

use bytes::{Bytes, BytesMut};
use citadel_sdk::citadel_media::config::MediaConfig;
use citadel_sdk::citadel_media::demux::{IvfHeader, IvfReader, WavReader};
use citadel_sdk::citadel_media::MediaStats;
use citadel_sdk::media::{
    MediaTransportConfig, RECOMMENDED_FRAGMENT_PAYLOAD, RECOMMENDED_UDP_PAYLOAD_BUDGET,
};
use std::time::Duration;

pub const AUDIO_FRAME_MICROS: u64 = 20_000;
pub const MAX_TEST_FRAME_BYTES: usize = 512 * 1024;

/// Loopback-tuned media transport config: generous jitter depth so slow CI
/// never mistakes scheduling delay for loss.
pub fn test_media_config() -> MediaTransportConfig {
    let cfg = MediaTransportConfig {
        media: MediaConfig {
            max_fragment_payload: RECOMMENDED_FRAGMENT_PAYLOAD,
            max_frame_bytes: MAX_TEST_FRAME_BYTES,
            max_reorder_window: 4096,
            jitter_depth_micros: 500_000,
            max_pending_frames: 1024,
        },
        send_queue_frames: 2048,
        udp_payload_budget: RECOMMENDED_UDP_PAYLOAD_BUDGET,
        udp_wait: Duration::from_secs(10),
    };
    cfg.validate().expect("test media config must be valid");
    cfg
}

/// Splits the fixture WAV into the exact 20 ms PCM chunks the sender streams.
/// Deterministic, so both test kernels and the assertion derive the same data.
pub fn wav_chunks(bytes: &[u8]) -> (u32, Vec<Bytes>) {
    let mut reader = WavReader::new(std::io::Cursor::new(bytes)).expect("fixture wav parses");
    let sample_rate = reader.format().sample_rate;
    let mut scratch = BytesMut::new();
    let mut chunks = Vec::new();
    while let Some(chunk) = reader
        .next_chunk(AUDIO_FRAME_MICROS, &mut scratch)
        .expect("wav chunk")
    {
        chunks.push(chunk);
    }
    (sample_rate, chunks)
}

/// All frames of the fixture IVF plus its header.
pub fn ivf_frames(bytes: &[u8]) -> (IvfHeader, Vec<(u64, Bytes)>) {
    let mut reader = IvfReader::new(std::io::Cursor::new(bytes), MAX_TEST_FRAME_BYTES)
        .expect("fixture ivf parses");
    let header = *reader.header();
    let mut scratch = BytesMut::new();
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame(&mut scratch).expect("ivf frame") {
        frames.push((frame.pts, frame.data));
    }
    (header, frames)
}

pub fn sha_of_parts<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> String {
    let mut all = Vec::new();
    for part in parts {
        all.extend_from_slice(part);
    }
    sha256::digest(all)
}

/// Tracks a receiver's `Frame`/`Gap` events against what the Unreliable transport
/// actually promises: frames in sequence order, every sequence either delivered or
/// inside exactly one reported `Gap`, and no completed frame silently discarded.
/// Loss itself is legal — a stalled receiver overflows the UDP socket buffer — so
/// only `finish_lossless` (for the Reliable transport) forbids gaps.
#[derive(Debug, Default)]
pub struct DeliveryLedger {
    next: u32,
    delivered: Vec<u32>,
    missing: u64,
}

impl DeliveryLedger {
    /// Records a delivered frame; returns its index in the sent stream.
    pub fn frame(&mut self, sequence: u32) -> usize {
        assert_eq!(
            sequence, self.next,
            "frames arrive in order, after any gap: {self:?}"
        );
        self.next += 1;
        self.delivered.push(sequence);
        sequence as usize
    }

    pub fn gap(&mut self, missing_from: u32, missing_to: u32) {
        assert_eq!(
            missing_from, self.next,
            "a gap starts where delivery stopped"
        );
        assert!(
            missing_to >= missing_from,
            "gap {missing_from}..={missing_to}"
        );
        self.next = missing_to + 1;
        self.missing += u64::from(missing_to - missing_from + 1);
    }

    pub fn delivered(&self) -> usize {
        self.delivered.len()
    }

    /// At end-of-stream: the ledger covers all `sent` frames and agrees with `stats`.
    pub fn finish_unreliable(&self, sent: usize, stats: &MediaStats) {
        assert_eq!(
            self.next as usize, sent,
            "every sequence delivered or reported missing"
        );
        assert_eq!(stats.frames_delivered, self.delivered.len() as u64);
        assert_eq!(stats.frames_missing, self.missing);
        assert_eq!(
            stats.frames_completed,
            stats.frames_delivered + stats.frames_late + stats.frames_too_old,
            "a frame the receiver completed was neither delivered nor counted late: {stats:?}"
        );
        assert!(!self.delivered.is_empty(), "the path carried no media");
    }

    pub fn finish_lossless(&self, sent: usize, stats: &MediaStats) {
        self.finish_unreliable(sent, stats);
        assert_eq!(self.missing, 0, "the reliable transport lost frames");
        assert_eq!(stats.gaps_skipped, 0);
    }
}
