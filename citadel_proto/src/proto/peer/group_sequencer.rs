//! The server's order of each group's broadcasts: the decisions, with no I/O.
//!
//! One [`GroupOrderBook`] lives inside the node's group fan-out lock
//! (`CitadelNodePeerLayer::group_order`), so every decision here is made by one broadcast at a
//! time, in the order the fan-out writes members' streams. A decision is taken first
//! ([`GroupOrderBook::next`]), persisted by the caller (`group_log`), and only then recorded
//! ([`GroupOrderBook::commit`]): a write that fails leaves the head where it was, so no number
//! is used without its broadcast stored.
//!
//! - A group without replay keeps its head in memory and reserves numbers in blocks of
//!   [`RESERVE_BLOCK`]: the end of a block is written before a number in it is given, so after a
//!   restart the head resumes past it. Numbers never repeat or go back; they may skip.
//! - A replay group stores every positioned broadcast in its log before the fan-out, so its
//!   head after a restart is the last stored entry and its numbers have no gaps from `since`.

use citadel_types::proto::{GroupLogLimits, GroupMessageId, GroupPosition, MessageGroupKey};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, VecDeque};

/// How many numbers a group without replay reserves at once.
pub(crate) const RESERVE_BLOCK: u64 = 1024;
/// How many message ids a group without replay remembers for retries (it has no log to rebuild
/// them from, so a retry is recognised only within this window and this server's run).
pub(crate) const RECENT_IDS_WITHOUT_REPLAY: usize = 1024;
const CHAIN_DOMAIN: &[u8] = b"citadel-group-log-v1";

/// One stored entry of a replay group's log, as far as the decisions need it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub seq: u64,
    pub bytes: usize,
    pub held_at_ns: i64,
    pub chain: [u8; 32],
    pub id: Option<(u64, GroupMessageId)>,
}

/// A replay group's log, as the decisions see it.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReplayLog {
    pub since: u64,
    pub limits: Option<GroupLogLimits>,
    pub chain: [u8; 32],
    /// The last position removed from the log (`since - 1` when none was).
    pub trimmed_through: u64,
    /// The chain head at `trimmed_through`.
    pub trimmed_chain: [u8; 32],
    pub entries: VecDeque<Entry>,
}

/// One group's order.
#[derive(Clone, Debug, Default)]
pub(crate) struct GroupOrder {
    /// The last number given.
    pub head: u64,
    /// The account the group's log and meta are stored under.
    pub holder: u64,
    /// Without replay: the end of the reserved block.
    pub reserved_through: u64,
    pub replay: Option<ReplayLog>,
    /// `(sender, id)` → position given.
    pub ids: HashMap<(u64, GroupMessageId), GroupPosition>,
    pub recent: VecDeque<(u64, GroupMessageId)>,
}

/// What the caller must persist before a decision may be committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Persist {
    Nothing,
    /// The new end of the reserved block.
    Reserve(u64),
    /// The broadcast goes into the log at this position.
    Log,
}

/// The decision for one broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// A new position, given once `persist` is done and the decision committed.
    New {
        position: GroupPosition,
        persist: Persist,
    },
    /// The same `(sender, id)` was given `position` already: answer it, relay nothing.
    Retry { position: GroupPosition },
}

/// The node's order of every group it relays.
#[derive(Default)]
pub struct GroupOrderBook {
    pub(crate) groups: HashMap<MessageGroupKey, GroupOrder>,
}

/// The chain head after `digest` (the SHA3-256 of the positioned frame) at `seq`.
pub(crate) fn chain_link(
    key: MessageGroupKey,
    seq: u64,
    previous: &[u8; 32],
    digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(CHAIN_DOMAIN);
    hasher.update(key.cid.to_be_bytes());
    hasher.update(key.mgid.to_be_bytes());
    hasher.update(seq.to_be_bytes());
    hasher.update(previous);
    hasher.update(digest);
    hasher.finalize().into()
}

/// The SHA3-256 of a frame's bytes.
pub(crate) fn digest(frame: &[u8]) -> [u8; 32] {
    Sha3_256::digest(frame).into()
}

impl GroupOrderBook {
    /// `key`'s order, created empty (numbering from 1) for a group this book has not seen: a
    /// group that existed before numbering, or a new one.
    pub(crate) fn order_mut(&mut self, key: MessageGroupKey, holder: u64) -> &mut GroupOrder {
        self.groups.entry(key).or_insert_with(|| GroupOrder {
            holder,
            ..Default::default()
        })
    }

    /// Whether `key` keeps a log.
    pub(crate) fn has_replay(&self, key: MessageGroupKey) -> bool {
        self.groups.get(&key).is_some_and(|g| g.replay.is_some())
    }

    /// The decision for the next broadcast to `key`, whose frame hashes to `digest`; `id` for a
    /// message (`(sender, id)`), `None` for control.
    pub(crate) fn next(
        &mut self,
        key: MessageGroupKey,
        holder: u64,
        id: Option<(u64, GroupMessageId)>,
        digest: &[u8; 32],
    ) -> Next {
        let order = self.order_mut(key, holder);
        if let Some(position) = id.and_then(|id| order.ids.get(&id)) {
            return Next::Retry {
                position: *position,
            };
        }
        let seq = order.head + 1;
        match &order.replay {
            Some(log) => Next::New {
                position: GroupPosition {
                    seq,
                    chain: Some(chain_link(key, seq, &log.chain, digest)),
                },
                persist: Persist::Log,
            },
            None => Next::New {
                position: GroupPosition { seq, chain: None },
                persist: if seq > order.reserved_through {
                    Persist::Reserve(order.reserved_through + RESERVE_BLOCK)
                } else {
                    Persist::Nothing
                },
            },
        }
    }

    /// Records a decision whose persistence is done.
    pub(crate) fn commit(
        &mut self,
        key: MessageGroupKey,
        next: &Next,
        id: Option<(u64, GroupMessageId)>,
        bytes: usize,
        held_at_ns: i64,
    ) {
        let Next::New { position, persist } = next else {
            return;
        };
        let Some(order) = self.groups.get_mut(&key) else {
            return;
        };
        order.head = position.seq;
        if let Persist::Reserve(through) = persist {
            order.reserved_through = *through;
        }
        if let (Some(log), Some(chain)) = (order.replay.as_mut(), position.chain) {
            log.chain = chain;
            log.entries.push_back(Entry {
                seq: position.seq,
                bytes,
                held_at_ns,
                chain,
                id,
            });
        }
        if let Some(id) = id {
            let _ = order.ids.insert(id, *position);
            if order.replay.is_none() {
                order.recent.push_back(id);
                while order.recent.len() > RECENT_IDS_WITHOUT_REPLAY {
                    if let Some(old) = order.recent.pop_front() {
                        let _ = order.ids.remove(&old);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "group_sequencer_tests.rs"]
mod tests;
