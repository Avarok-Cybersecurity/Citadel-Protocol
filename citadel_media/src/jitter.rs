use crate::config::MediaConfig;
use crate::error::MediaError;
use crate::frame::{MediaFrame, TrackId};
use crate::time::MediaInstant;

/// Outcome of [`JitterBuffer::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    Buffered,
    /// Frame precedes `next_expected` but lies within `max_reorder_window`: it was already
    /// skipped or delivered, so it is dropped.
    Late,
    /// Frame is older than `max_reorder_window` behind `next_expected`.
    TooOld,
    Duplicate,
}

/// Outcome of [`JitterBuffer::pop_ready`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PopResult {
    Frame(MediaFrame),
    /// `missing_from..=missing_to` never arrived within `jitter_depth_micros`; `next` follows.
    Gap {
        track: TrackId,
        missing_from: u32,
        missing_to: u32,
        next: MediaFrame,
    },
    NotReady,
}

#[derive(Debug)]
struct Entry {
    frame: MediaFrame,
    arrived: MediaInstant,
}

#[derive(Debug)]
struct TrackState {
    next_expected: Option<u32>,
    entries: Vec<Entry>,
}

/// Reorders frames per track by wrapping sequence number and skips gaps after a bounded wait.
#[derive(Debug)]
pub struct JitterBuffer {
    config: MediaConfig,
    tracks: Vec<TrackState>,
}

#[inline]
const fn seq_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

impl JitterBuffer {
    pub fn new(config: MediaConfig) -> Result<Self, MediaError> {
        config.validate()?;
        Ok(Self {
            config,
            tracks: Vec::new(),
        })
    }

    pub fn buffered_len(&self) -> usize {
        self.tracks.iter().map(|t| t.entries.len()).sum()
    }

    pub fn next_expected(&self, track: TrackId) -> Option<u32> {
        self.tracks.get(track.index()).and_then(|t| t.next_expected)
    }

    fn track_mut(&mut self, track: TrackId) -> &mut TrackState {
        let idx = track.index();
        while self.tracks.len() <= idx {
            self.tracks.push(TrackState {
                next_expected: None,
                entries: Vec::new(),
            });
        }
        &mut self.tracks[idx]
    }

    pub fn push(&mut self, frame: MediaFrame, now: MediaInstant) -> PushResult {
        let window = self.config.max_reorder_window as i32;
        let state = self.track_mut(frame.header.track);
        let seq = frame.header.sequence;
        // Before the track locks on (first pop after the hold-back window), every distinct
        // frame is buffered: locking onto the first *arrival* would misclassify reordered
        // earlier frames as `Late` and drop them.
        if let Some(next) = state.next_expected {
            let diff = seq_diff(seq, next);
            if diff < 0 {
                return if -diff > window {
                    PushResult::TooOld
                } else {
                    PushResult::Late
                };
            }
        }
        if state.entries.iter().any(|e| e.frame.header.sequence == seq) {
            return PushResult::Duplicate;
        }
        state.entries.push(Entry {
            frame,
            arrived: now,
        });
        PushResult::Buffered
    }

    /// Emits the next in-order frame, or skips a gap once the oldest buffered frame on a
    /// track has waited at least `jitter_depth_micros`. Tracks are scanned in id order.
    pub fn pop_ready(&mut self, now: MediaInstant) -> PopResult {
        let depth = self.config.jitter_depth_micros;
        for state in &mut self.tracks {
            if state.entries.is_empty() {
                continue;
            }
            let next = match state.next_expected {
                Some(next) => next,
                None => {
                    // Lock-on: once the earliest-arrived frame has aged through the hold-back
                    // window, playout starts at the lowest buffered sequence (anchored to the
                    // earliest arrival so u32 wrap during pre-lock stays correct).
                    let oldest = state
                        .entries
                        .iter()
                        .min_by_key(|e| e.arrived)
                        .expect("non-empty checked above");
                    if now.micros_since(oldest.arrived) < depth {
                        continue;
                    }
                    let anchor = oldest.frame.header.sequence;
                    let lowest = state
                        .entries
                        .iter()
                        .map(|e| e.frame.header.sequence)
                        .min_by_key(|&s| seq_diff(s, anchor))
                        .expect("non-empty checked above");
                    state.next_expected = Some(lowest);
                    lowest
                }
            };
            if let Some(i) = state
                .entries
                .iter()
                .position(|e| e.frame.header.sequence == next)
            {
                let entry = state.entries.swap_remove(i);
                state.next_expected = Some(next.wrapping_add(1));
                return PopResult::Frame(entry.frame);
            }
            let lowest_seq_idx = state
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| seq_diff(e.frame.header.sequence, next))
                .map(|(i, _)| i)
                .expect("non-empty checked above");
            let waited = state
                .entries
                .iter()
                .map(|e| now.micros_since(e.arrived))
                .max()
                .expect("non-empty checked above");
            if waited < depth {
                continue;
            }
            let entry = state.entries.swap_remove(lowest_seq_idx);
            let seq = entry.frame.header.sequence;
            state.next_expected = Some(seq.wrapping_add(1));
            return PopResult::Gap {
                track: entry.frame.header.track,
                missing_from: next,
                missing_to: seq.wrapping_sub(1),
                next: entry.frame,
            };
        }
        PopResult::NotReady
    }

    /// Earliest instant at which [`pop_ready`](Self::pop_ready) may return something new.
    /// `None` when nothing is buffered. If an in-order frame is buffered, returns its arrival.
    pub fn next_deadline(&self) -> Option<MediaInstant> {
        let depth = self.config.jitter_depth_micros;
        let mut earliest: Option<MediaInstant> = None;
        for state in &self.tracks {
            for e in &state.entries {
                let at = match state.next_expected {
                    Some(next) if e.frame.header.sequence == next => e.arrived,
                    // Gap-skip (locked) and lock-on (unlocked) both mature `depth` after arrival.
                    _ => e.arrived.saturating_add_micros(depth),
                };
                earliest = Some(earliest.map_or(at, |cur| cur.min(at)));
            }
        }
        earliest
    }
}

#[cfg(test)]
mod tests {
    use super::seq_diff;

    #[test]
    fn wrapping_diff() {
        assert_eq!(seq_diff(0, u32::MAX), 1);
        assert_eq!(seq_diff(u32::MAX, 0), -1);
        assert_eq!(seq_diff(5, 2), 3);
    }
}
