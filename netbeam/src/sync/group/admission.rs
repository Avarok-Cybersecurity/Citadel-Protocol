//! Write-preferring FIFO admission rule (the etcd RWMutex / tokio::sync::RwLock policy),
//! the single source of truth for both `NetGroupMutex` and `NetGroupRwLock`:
//!
//! - a WRITE entry is admissible iff nothing is held and it is the queue head
//!   (a writer waits on ANY earlier entry);
//! - a READ entry is admissible iff the lock is free or held by readers AND no write
//!   entry is queued ahead of it (a reader waits only on earlier writers);
//!
//! hence the admissible readers at any instant are exactly the queue prefix before the
//! first queued writer — reader *batching* falls out, and a queued writer blocks every
//! later reader, so writers cannot starve.

use crate::sync::group::record::{Holders, LockRecord, WaitEntry};
use crate::sync::group::{LockKind, MemberId};

/// Whether the queue entry `(member, nonce)` could be granted right now.
pub fn is_admissible(record: &LockRecord, member: MemberId, nonce: u64) -> bool {
    let Some((idx, entry)) = record.wait_entry(member, nonce) else {
        return false;
    };
    match entry.kind {
        LockKind::Write => matches!(record.holders, Holders::None) && idx == 0,
        LockKind::Read => {
            let holders_compatible = matches!(record.holders, Holders::None | Holders::Readers(_));
            holders_compatible
                && !record.queue[..idx]
                    .iter()
                    .any(|w| w.kind == LockKind::Write)
        }
    }
}

/// Whether a brand-new request (not yet queued) could be granted immediately,
/// i.e. admissibility as if appended at the queue tail.
pub fn immediate_grant_allowed(record: &LockRecord, kind: LockKind) -> bool {
    match kind {
        LockKind::Write => matches!(record.holders, Holders::None) && record.queue.is_empty(),
        LockKind::Read => {
            matches!(record.holders, Holders::None | Holders::Readers(_))
                && !record.queue.iter().any(|w| w.kind == LockKind::Write)
        }
    }
}

/// The members whose queue entries just became (or may have become) admissible —
/// the targets a releaser nudges. Returns either the head writer or the whole
/// reader prefix, never both (no herd effect).
pub fn next_grants(record: &LockRecord) -> Vec<MemberId> {
    let mut targets: Vec<MemberId> = Vec::new();
    match record.queue.first().map(|w| w.kind) {
        Some(LockKind::Write) => {
            if matches!(record.holders, Holders::None) {
                targets.push(record.queue[0].member);
            }
        }
        Some(LockKind::Read) => {
            if matches!(record.holders, Holders::None | Holders::Readers(_)) {
                for w in reader_prefix(record) {
                    if !targets.contains(&w.member) {
                        targets.push(w.member);
                    }
                }
            }
        }
        None => {}
    }
    targets
}

fn reader_prefix(record: &LockRecord) -> impl Iterator<Item = &WaitEntry> {
    record.queue.iter().take_while(|w| w.kind == LockKind::Read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::group::record::HolderEntry;
    use crate::sync::group::Fence;

    fn wait(member: u64, nonce: u64, kind: LockKind) -> WaitEntry {
        WaitEntry {
            member: MemberId(member),
            nonce,
            kind,
            refresh_seq: 0,
        }
    }

    fn holder(member: u64) -> HolderEntry {
        HolderEntry {
            member: MemberId(member),
            nonce: 0,
            fence: Fence(1),
            lease_seq: 0,
            recovered: None,
        }
    }

    fn record(holders: Holders, queue: Vec<WaitEntry>) -> LockRecord {
        let mut r = LockRecord::initial(vec![]);
        r.holders = holders;
        r.queue = queue;
        r
    }

    #[test]
    fn writer_admissible_only_at_head_of_free_lock() {
        let r = record(
            Holders::None,
            vec![wait(1, 1, LockKind::Write), wait(2, 2, LockKind::Write)],
        );
        assert!(is_admissible(&r, MemberId(1), 1));
        assert!(!is_admissible(&r, MemberId(2), 2));

        let r = record(
            Holders::Readers(vec![holder(3)]),
            vec![wait(1, 1, LockKind::Write)],
        );
        assert!(!is_admissible(&r, MemberId(1), 1));
    }

    #[test]
    fn reader_blocked_by_earlier_writer_only() {
        let r = record(
            Holders::None,
            vec![
                wait(1, 1, LockKind::Read),
                wait(2, 2, LockKind::Write),
                wait(3, 3, LockKind::Read),
            ],
        );
        assert!(is_admissible(&r, MemberId(1), 1));
        assert!(!is_admissible(&r, MemberId(3), 3)); // behind the queued writer
    }

    #[test]
    fn readers_batch_alongside_current_readers() {
        let r = record(
            Holders::Readers(vec![holder(9)]),
            vec![wait(1, 1, LockKind::Read), wait(2, 2, LockKind::Read)],
        );
        assert!(is_admissible(&r, MemberId(1), 1));
        assert!(is_admissible(&r, MemberId(2), 2));
        assert_eq!(next_grants(&r), vec![MemberId(1), MemberId(2)]);
    }

    #[test]
    fn immediate_grant_respects_write_preference() {
        let free = record(Holders::None, vec![]);
        assert!(immediate_grant_allowed(&free, LockKind::Write));
        assert!(immediate_grant_allowed(&free, LockKind::Read));

        // a queued writer bars new readers even while readers hold the lock
        let r = record(
            Holders::Readers(vec![holder(9)]),
            vec![wait(1, 1, LockKind::Write)],
        );
        assert!(!immediate_grant_allowed(&r, LockKind::Read));
        assert!(!immediate_grant_allowed(&r, LockKind::Write));
    }

    #[test]
    fn next_grants_head_writer_when_free() {
        let r = record(
            Holders::None,
            vec![wait(2, 2, LockKind::Write), wait(1, 1, LockKind::Read)],
        );
        assert_eq!(next_grants(&r), vec![MemberId(2)]);
        let held = record(
            Holders::Writer(holder(9)),
            vec![wait(2, 2, LockKind::Write)],
        );
        assert!(next_grants(&held).is_empty());
    }
}
