//! A replay group's log, kept within its limits, and the ranges read from it: the decisions,
//! with no I/O (`group_log` stores what these decide).

use super::group_sequencer::{GroupOrder, ReplayLog};
use citadel_types::proto::GroupLogLimits;

/// The most entries one fetch answer, or one turn of a replay, carries. A replay sends turn by
/// turn, releasing the node's fan-out lock between turns (`group_order_replay`).
pub(crate) const MAX_RANGE_ENTRIES: usize = 256;

/// What a read of positions `(after, until]` finds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Range {
    /// Part of the range is older than the log keeps; the log starts at `earliest`.
    Trimmed { earliest: u64 },
    /// The positions to send, in order (at most [`MAX_RANGE_ENTRIES`]); empty when there is
    /// nothing after `after`.
    Seqs(Vec<u64>),
}

impl ReplayLog {
    /// A log starting at `since` under `limits`.
    pub(crate) fn starting_at(since: u64, limits: GroupLogLimits) -> Self {
        Self {
            since,
            limits: Some(limits),
            chain: [0u8; 32],
            trimmed_through: since - 1,
            trimmed_chain: [0u8; 32],
            entries: Default::default(),
        }
    }

    /// The first position the log still holds (or will hold next, when it is empty).
    pub(crate) fn earliest(&self) -> u64 {
        self.trimmed_through + 1
    }

    /// The positions of `(after, until]` this log can answer, capped at `max`; a member that
    /// holds nothing from the log yet (`after` before `since`) starts at `since`.
    pub(crate) fn range(&self, head: u64, after: u64, until: u64, max: usize) -> Range {
        let start = (after + 1).max(self.since);
        if start < self.earliest() {
            return Range::Trimmed {
                earliest: self.earliest(),
            };
        }
        let last = until.min(head);
        let seqs = self
            .entries
            .iter()
            .map(|entry| entry.seq)
            .filter(|seq| *seq >= start && *seq <= last)
            .take(max)
            .collect();
        Range::Seqs(seqs)
    }

    /// The positions to drop so the log is within its limits at `now_ns`, oldest first, and the
    /// new `trimmed_through`; `None` when it already is.
    pub(crate) fn over_limits(&self, now_ns: i64) -> Option<(Vec<u64>, u64)> {
        let limits = self.limits?;
        let max_age_ns = i64::try_from(limits.max_age.as_nanos()).unwrap_or(i64::MAX);
        let mut count = self.entries.len();
        let mut bytes: u64 = self.entries.iter().map(|e| e.bytes as u64).sum();
        let mut dropped = Vec::new();
        for entry in &self.entries {
            let too_many = count > limits.max_messages as usize;
            let too_big = bytes > limits.max_bytes;
            let too_old = now_ns.saturating_sub(entry.held_at_ns) > max_age_ns;
            if !(too_many || too_big || too_old) {
                break;
            }
            dropped.push(entry.seq);
            count -= 1;
            bytes -= entry.bytes as u64;
        }
        let through = *dropped.last()?;
        Some((dropped, through))
    }
}

impl GroupOrder {
    /// Turns replay on from the next position, under `limits`. `None` when it is on already.
    pub(crate) fn enable_replay(&mut self, limits: GroupLogLimits) -> Option<u64> {
        if self.replay.is_some() {
            return None;
        }
        let since = self.head + 1;
        // Nothing past the head was given: the log's numbers follow on from it.
        self.reserved_through = self.head;
        self.replay = Some(ReplayLog::starting_at(since, limits));
        self.ids.clear();
        Some(since)
    }

    /// Records that the log's positions up to `through` were removed.
    pub(crate) fn trimmed(&mut self, through: u64) {
        let Some(log) = self.replay.as_mut() else {
            return;
        };
        log.trimmed_through = log.trimmed_through.max(through);
        while log.entries.front().is_some_and(|e| e.seq <= through) {
            if let Some(entry) = log.entries.pop_front() {
                log.trimmed_chain = entry.chain;
                if let Some(id) = entry.id {
                    let _ = self.ids.remove(&id);
                }
            }
        }
    }
}

// Tested with the sequencer (`group_sequencer_tests.rs`).
