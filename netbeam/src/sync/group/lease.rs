//! Pure lease/janitor arithmetic. All instants are `millis` on the LOCAL monotonic
//! clock (the driver supplies them); no cross-node clock value is ever compared.
//!
//! The steal rule (DynamoDB-lock-client pattern): freeze a snapshot of the blocker's
//! progress counters at first observation; if, after `lease_duration + steal_grace`
//! measured on the observer's own clock, the counters have not advanced, the blocker
//! is steal-eligible. The CAS precondition re-checks the frozen snapshot, so a holder
//! that advanced concurrently denies the steal — hints (like stream disconnects) may
//! start observation early but can never force a transfer.

use crate::sync::group::record::{HolderEntry, LockRecord, WaitEntry};
use crate::sync::group::MemberId;

/// Progress snapshot of a queue/holder entry that blocks us.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlockerSnapshot {
    Holder {
        member: MemberId,
        nonce: u64,
        fence: crate::sync::group::Fence,
        lease_seq: u64,
    },
    Waiter {
        member: MemberId,
        nonce: u64,
        refresh_seq: u64,
    },
}

impl BlockerSnapshot {
    pub fn of_holder(h: &HolderEntry) -> Self {
        Self::Holder {
            member: h.member,
            nonce: h.nonce,
            fence: h.fence,
            lease_seq: h.lease_seq,
        }
    }

    pub fn of_waiter(w: &WaitEntry) -> Self {
        Self::Waiter {
            member: w.member,
            nonce: w.nonce,
            refresh_seq: w.refresh_seq,
        }
    }
}

/// Tracks one blocker's observed (im)mobility on the local clock.
#[derive(Clone, Debug)]
pub struct ObservationWindow {
    snapshot: BlockerSnapshot,
    first_observed_ms: u64,
}

impl ObservationWindow {
    pub fn start(snapshot: BlockerSnapshot, now_ms: u64) -> Self {
        Self {
            snapshot,
            first_observed_ms: now_ms,
        }
    }

    /// Re-observe. If the blocker advanced, the window restarts at `now_ms`.
    /// Returns `true` if the snapshot was stagnant (window preserved).
    pub fn observe(&mut self, current: BlockerSnapshot, now_ms: u64) -> bool {
        if current == self.snapshot {
            true
        } else {
            self.snapshot = current;
            self.first_observed_ms = now_ms;
            false
        }
    }

    pub fn snapshot(&self) -> &BlockerSnapshot {
        &self.snapshot
    }

    /// Steal/evict eligibility: stagnant for at least the full window.
    pub fn is_expired(&self, now_ms: u64, window_ms: u64) -> bool {
        now_ms.saturating_sub(self.first_observed_ms) >= window_ms
    }
}

/// The single entry currently blocking `(member, nonce)`'s queue progress, if any:
/// for a queued writer, the current holder set's first entry or its queue predecessor;
/// for a queued reader, the nearest earlier queued writer or the current writer.
/// Returns the snapshot the janitor should watch. `None` = nothing blocks (claim!).
pub fn blocking_snapshot(
    record: &LockRecord,
    member: MemberId,
    nonce: u64,
) -> Option<BlockerSnapshot> {
    use crate::sync::group::record::Holders;
    use crate::sync::group::LockKind;

    let (idx, entry) = record.wait_entry(member, nonce)?;
    match entry.kind {
        LockKind::Write => {
            if idx > 0 {
                return Some(BlockerSnapshot::of_waiter(&record.queue[idx - 1]));
            }
            match &record.holders {
                Holders::None => None,
                Holders::Writer(h) => Some(BlockerSnapshot::of_holder(h)),
                // watch the reader batch's slowest-visible entry: any stagnant one
                // must drain, so observe the first (they are stolen individually)
                Holders::Readers(hs) => hs.first().map(BlockerSnapshot::of_holder),
            }
        }
        LockKind::Read => {
            if let Some(w) = record.queue[..idx]
                .iter()
                .rev()
                .find(|w| w.kind == LockKind::Write)
            {
                return Some(BlockerSnapshot::of_waiter(w));
            }
            match &record.holders {
                Holders::Writer(h) => Some(BlockerSnapshot::of_holder(h)),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::group::record::{Holders, LockRecord};
    use crate::sync::group::{Fence, LockKind};

    #[test]
    fn window_restarts_when_blocker_advances() {
        let snap = BlockerSnapshot::Waiter {
            member: MemberId(1),
            nonce: 1,
            refresh_seq: 0,
        };
        let mut w = ObservationWindow::start(snap, 1000);
        assert!(!w.is_expired(1500, 1000));
        assert!(w.observe(snap, 1500));
        assert!(w.is_expired(2000, 1000));

        let advanced = BlockerSnapshot::Waiter {
            member: MemberId(1),
            nonce: 1,
            refresh_seq: 1,
        };
        assert!(!w.observe(advanced, 2000));
        assert!(!w.is_expired(2500, 1000));
        assert!(w.is_expired(3000, 1000));
    }

    #[test]
    fn blocking_snapshot_selection() {
        let mut rec = LockRecord::initial(vec![]);
        rec.holders = Holders::Writer(HolderEntry {
            member: MemberId(9),
            nonce: 90,
            fence: Fence(3),
            lease_seq: 2,
            recovered: None,
        });
        rec.queue = vec![
            WaitEntry {
                member: MemberId(1),
                nonce: 10,
                kind: LockKind::Write,
                refresh_seq: 0,
            },
            WaitEntry {
                member: MemberId(2),
                nonce: 20,
                kind: LockKind::Read,
                refresh_seq: 5,
            },
        ];
        // head writer watches the current writer-holder
        assert_eq!(
            blocking_snapshot(&rec, MemberId(1), 10),
            Some(BlockerSnapshot::Holder {
                member: MemberId(9),
                nonce: 90,
                fence: Fence(3),
                lease_seq: 2
            })
        );
        // the reader behind the queued writer watches that writer's wait entry
        assert_eq!(
            blocking_snapshot(&rec, MemberId(2), 20),
            Some(BlockerSnapshot::Waiter {
                member: MemberId(1),
                nonce: 10,
                refresh_seq: 0
            })
        );
        // free lock + head of queue = nothing blocking
        rec.holders = Holders::None;
        assert_eq!(blocking_snapshot(&rec, MemberId(1), 10), None);
    }
}
