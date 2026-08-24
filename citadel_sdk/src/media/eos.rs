//! Deferred end-of-stream resolution: an `EndOfStream { track, frames_sent }`
//! control message may outrace in-flight media, so it is held until the
//! track's delivery reaches `frames_sent` or a jitter-depth deadline passes.
use super::receiver::MediaEvent;
use citadel_media::{MediaInstant, MediaStats, TrackId};
use std::collections::VecDeque;

/// A pending end-of-stream announcement: surfaced once the track's delivery
/// reaches `final_seq`, or force-closed (with a `Gap`) when `deadline` passes.
#[derive(Debug, Clone, Copy)]
struct EosRecord {
    track: TrackId,
    final_seq: u32,
    deadline: MediaInstant,
}

/// Same wrapping sequence arithmetic as the jitter buffer.
#[inline]
const fn seq_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

#[derive(Debug)]
pub(super) struct EosTracker {
    records: Vec<EosRecord>,
    /// From the validated `MediaConfig`; bounds how long an EOS may wait.
    jitter_depth_micros: u64,
}

impl EosTracker {
    pub(super) fn new(jitter_depth_micros: u64) -> Self {
        Self {
            records: Vec::new(),
            jitter_depth_micros,
        }
    }

    pub(super) fn record(&mut self, track: TrackId, frames_sent: u32, now: MediaInstant) {
        self.records.push(EosRecord {
            track,
            final_seq: frames_sent,
            deadline: now.saturating_add_micros(self.jitter_depth_micros),
        });
    }

    pub(super) fn next_deadline(&self) -> impl Iterator<Item = MediaInstant> + '_ {
        self.records.iter().map(|rec| rec.deadline)
    }

    /// Resolves pending records: a track whose delivery reached `final_seq`
    /// emits `EndOfStream`; one whose deadline passed (or whose transport
    /// closed, `force`) emits a `Gap` over the lost tail first. Returns
    /// whether any event was queued.
    pub(super) fn resolve(
        &mut self,
        now: MediaInstant,
        force: bool,
        next_expected: impl Fn(TrackId) -> Option<u32>,
        ready: &mut VecDeque<MediaEvent>,
        stats: &mut MediaStats,
    ) -> bool {
        let mut queued = false;
        let mut i = 0;
        while i < self.records.len() {
            let rec = self.records[i];
            let next = next_expected(rec.track);
            let complete = match next {
                Some(n) => seq_diff(n, rec.final_seq) >= 0,
                None => rec.final_seq == 0,
            };
            if complete {
                let _ = self.records.swap_remove(i);
                ready.push_back(MediaEvent::EndOfStream(rec.track));
                queued = true;
                continue;
            }
            if force || now >= rec.deadline {
                let _ = self.records.swap_remove(i);
                let missing_from = next.unwrap_or(0);
                let missing = seq_diff(rec.final_seq, missing_from);
                if missing > 0 {
                    stats.gaps_skipped += 1;
                    stats.frames_missing += missing as u64;
                    ready.push_back(MediaEvent::Gap {
                        track: rec.track,
                        missing_from,
                        missing_to: rec.final_seq.wrapping_sub(1),
                    });
                }
                ready.push_back(MediaEvent::EndOfStream(rec.track));
                queued = true;
                continue;
            }
            i += 1;
        }
        queued
    }
}
