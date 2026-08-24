//! The replicated lock state. One `LockRecord` per lock is the single source of truth,
//! maintained by consensus rounds; every field transition happens through
//! [`crate::sync::group::ops::apply`].

use crate::sync::group::{Fence, LockKind, MemberId};
use serde::{Deserialize, Serialize};

/// One granted holder. `(member, nonce)` identifies the requester instance
/// (nonce is minted per acquire, so a restarted process never aliases an old grant).
/// `lease_seq` increments on every successful renew; observers detect a live holder
/// by watching `(fence, lease_seq)` advance.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct HolderEntry {
    pub member: MemberId,
    pub nonce: u64,
    pub fence: Fence,
    pub lease_seq: u64,
    /// Poison consumed by this grant (write grants only). Kept in the entry so a
    /// retried acquire/claim round reports the same `recovered` info (idempotency),
    /// and so a cancel-races-grant dequeue can restore it.
    pub recovered: Option<PoisonInfo>,
}

/// One queued waiter. `refresh_seq` increments on every waiter heartbeat
/// (`Op::RefreshWait`); stagnant waiters are evicted by whoever they block.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct WaitEntry {
    pub member: MemberId,
    pub nonce: u64,
    pub kind: LockKind,
    pub refresh_seq: u64,
}

/// Current holder set: exclusive writer or a batch of concurrent readers.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub enum Holders {
    #[default]
    None,
    Writer(HolderEntry),
    Readers(Vec<HolderEntry>),
}

/// Set when a writer was stolen mid-critical-section; consumed (reported as
/// `recovered = true`) by the next write grant.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PoisonInfo {
    pub member: MemberId,
    pub fence: Fence,
}

/// The consensus-replicated lock register. The protected value travels inside the
/// record (as caller-serialized bytes), so a release and its value publication commit
/// in one atomic CAS: a crashed writer's uncommitted mutations are invisible by
/// construction because only its own successful release could have advanced
/// `value` / `value_version`.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct LockRecord {
    /// Last minted fence; a new grant's fence is `fence_counter + 1`.
    pub fence_counter: u64,
    /// Serialized protected value (authoritative snapshot).
    pub value: Vec<u8>,
    /// Fence of the write grant that committed `value` (0 = initial value).
    pub value_version: Fence,
    pub poisoned: Option<PoisonInfo>,
    /// Per-member tombstone of the most recent voluntary release
    /// `(member, nonce, fence)` — makes a replayed `Release` after an ambiguous
    /// committed round idempotent. One slot PER MEMBER (not one global slot):
    /// other members' releases can commit between a release's committed round and
    /// its replay (dueling-proposer retry), and a single shared slot would then
    /// misreport the replay as `NotHolder`/`Stolen`. Bounded by the membership
    /// size, since a member's next release cannot commit while its previous
    /// release proposal is still in flight.
    pub released: Vec<(MemberId, u64, Fence)>,
    pub holders: Holders,
    /// FIFO queue; arrival order == CAS serialization order.
    pub queue: Vec<WaitEntry>,
}

impl LockRecord {
    pub fn initial(value: Vec<u8>) -> Self {
        Self {
            fence_counter: 0,
            value,
            value_version: Fence(0),
            poisoned: None,
            released: Vec::new(),
            holders: Holders::None,
            queue: Vec::new(),
        }
    }

    /// Mints the next fence, advancing the counter. `None` when the counter space
    /// is exhausted (defensive: only reachable via a hostile hand-crafted record).
    pub(crate) fn next_fence(&mut self) -> Option<Fence> {
        self.fence_counter = self.fence_counter.checked_add(1)?;
        Some(Fence(self.fence_counter))
    }

    /// Structural sanity bound for wire-derived records: counters far enough from
    /// exhaustion that protocol arithmetic cannot overflow.
    pub(crate) fn is_sane(&self) -> bool {
        const SLACK: u64 = 1 << 16;
        let bound = u64::MAX - SLACK;
        let holders_ok = match &self.holders {
            Holders::None => true,
            Holders::Writer(h) => h.lease_seq < bound && h.fence.0 <= self.fence_counter,
            Holders::Readers(hs) => hs
                .iter()
                .all(|h| h.lease_seq < bound && h.fence.0 <= self.fence_counter),
        };
        self.fence_counter < bound && holders_ok && self.queue.iter().all(|w| w.refresh_seq < bound)
    }

    /// The holder entry for `(member, nonce)`, if currently granted.
    pub fn holder(&self, member: MemberId, nonce: u64) -> Option<&HolderEntry> {
        match &self.holders {
            Holders::None => None,
            Holders::Writer(h) => (h.member == member && h.nonce == nonce).then_some(h),
            Holders::Readers(hs) => hs.iter().find(|h| h.member == member && h.nonce == nonce),
        }
    }

    pub(crate) fn holder_mut(&mut self, member: MemberId, nonce: u64) -> Option<&mut HolderEntry> {
        match &mut self.holders {
            Holders::None => None,
            Holders::Writer(h) => (h.member == member && h.nonce == nonce).then_some(h),
            Holders::Readers(hs) => hs
                .iter_mut()
                .find(|h| h.member == member && h.nonce == nonce),
        }
    }

    /// Removes the holder entry for `(member, nonce)`. Returns the removed entry and
    /// whether it held Write mode.
    pub(crate) fn remove_holder(
        &mut self,
        member: MemberId,
        nonce: u64,
    ) -> Option<(HolderEntry, LockKind)> {
        match &mut self.holders {
            Holders::None => None,
            Holders::Writer(h) => {
                if h.member == member && h.nonce == nonce {
                    let h = h.clone();
                    self.holders = Holders::None;
                    Some((h, LockKind::Write))
                } else {
                    None
                }
            }
            Holders::Readers(hs) => {
                let idx = hs
                    .iter()
                    .position(|h| h.member == member && h.nonce == nonce)?;
                let h = hs.remove(idx);
                if hs.is_empty() {
                    self.holders = Holders::None;
                }
                Some((h, LockKind::Read))
            }
        }
    }

    /// `true` iff `(member, nonce, fence)` matches that member's release tombstone
    /// (i.e. this exact release already committed and is being replayed).
    pub(crate) fn was_released(&self, member: MemberId, nonce: u64, fence: Fence) -> bool {
        self.released.contains(&(member, nonce, fence))
    }

    /// Records `(member, nonce, fence)` as that member's most recent committed
    /// release, replacing the member's previous tombstone.
    pub(crate) fn note_release(&mut self, member: MemberId, nonce: u64, fence: Fence) {
        self.released.retain(|(m, _, _)| *m != member);
        self.released.push((member, nonce, fence));
    }

    pub fn wait_entry(&self, member: MemberId, nonce: u64) -> Option<(usize, &WaitEntry)> {
        self.queue
            .iter()
            .enumerate()
            .find(|(_, w)| w.member == member && w.nonce == nonce)
    }

    pub(crate) fn remove_wait_entry(&mut self, member: MemberId, nonce: u64) -> Option<WaitEntry> {
        let idx = self
            .queue
            .iter()
            .position(|w| w.member == member && w.nonce == nonce)?;
        Some(self.queue.remove(idx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holder(member: u64, nonce: u64) -> HolderEntry {
        HolderEntry {
            member: MemberId(member),
            nonce,
            fence: Fence(1),
            lease_seq: 0,
            recovered: None,
        }
    }

    #[test]
    fn fence_minting_is_strictly_monotonic() {
        let mut r = LockRecord::initial(vec![]);
        let a = r.next_fence().unwrap();
        let b = r.next_fence().unwrap();
        assert!(b > a);
        assert_eq!(r.fence_counter, 2);
    }

    #[test]
    fn remove_last_reader_collapses_to_none() {
        let mut r = LockRecord::initial(vec![]);
        r.holders = Holders::Readers(vec![holder(1, 10), holder(2, 20)]);
        assert_eq!(
            r.remove_holder(MemberId(1), 10).map(|(_, k)| k),
            Some(LockKind::Read)
        );
        assert!(matches!(&r.holders, Holders::Readers(hs) if hs.len() == 1));
        r.remove_holder(MemberId(2), 20).unwrap();
        assert_eq!(r.holders, Holders::None);
        assert!(r.remove_holder(MemberId(2), 20).is_none());
    }

    #[test]
    fn holder_lookup_requires_matching_nonce() {
        let mut r = LockRecord::initial(vec![]);
        r.holders = Holders::Writer(holder(1, 10));
        assert!(r.holder(MemberId(1), 10).is_some());
        assert!(r.holder(MemberId(1), 11).is_none());
        assert!(r.remove_holder(MemberId(1), 11).is_none());
    }
}
