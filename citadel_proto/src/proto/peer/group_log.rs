//! Where a group's order is stored: the I/O behind [`GroupOrderBook`](super::group_sequencer).
//!
//! Under the account the group's row is under (its owner; see `group_persistence`), in the
//! byte map every backend implements:
//! - `(holder, 0, "group_order", <group id>)` → the group's [`StoredOrder`]: the end of its
//!   reserved block, and, for a replay group, where its log starts, its limits and how far it
//!   was trimmed. Written when a block is reserved, when replay is turned on, before a trim.
//! - `(holder, 0, "group_log/<group id>", <seq:020>)` → one [`StoredEntry`] per position of a
//!   replay group, written before the broadcast is fanned out.
//!
//! A group's order is read back when the server starts: its head is the last stored entry, or the
//! end of the reserved block, or how far it was trimmed, whichever is furthest, so a number is
//! never given twice.

use super::group_sequencer::{Entry, GroupOrder, ReplayLog};
use crate::error::NetworkError;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupLogLimits, GroupMessageId, MessageGroupKey};
use citadel_user::backend::PersistenceHandler;
use citadel_user::serialization::SyncIO;
use serde::{Deserialize, Serialize};

pub(super) const ORDERS: &str = "group_order";
pub(super) const NO_PEER: u64 = 0;

/// A group's order as stored.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredOrder {
    reserved_through: u64,
    replay: Option<StoredReplay>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct StoredReplay {
    since: u64,
    limits: GroupLogLimits,
    trimmed_through: u64,
    /// The chain head at `trimmed_through`, so an emptied log chains on from it.
    trimmed_chain: [u8; 32],
}

/// One position of a replay group's log as stored: the positioned frame, as sent.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredEntry {
    pub held_at_ns: i64,
    pub chain: [u8; 32],
    pub id: Option<(u64, GroupMessageId)>,
    pub frame: Vec<u8>,
}

pub(super) fn group_id(key: MessageGroupKey) -> String {
    format!("{:016x}-{:032x}", key.cid, key.mgid)
}

pub(super) fn log_map(key: MessageGroupKey) -> String {
    format!("group_log/{}", group_id(key))
}

pub(super) fn seq_key(seq: u64) -> String {
    format!("{seq:020}")
}

pub(super) fn io_error(what: &str, err: impl std::fmt::Display) -> NetworkError {
    NetworkError::msg(format!("group order: unable to {what}: {err}"))
}

impl StoredOrder {
    pub(crate) fn of(order: &GroupOrder) -> Self {
        Self {
            reserved_through: order.reserved_through,
            replay: order.replay.as_ref().and_then(|log| {
                Some(StoredReplay {
                    since: log.since,
                    limits: log.limits?,
                    trimmed_through: log.trimmed_through,
                    trimmed_chain: log.trimmed_chain,
                })
            }),
        }
    }
}

/// Writes `order`'s meta under its holder.
pub(crate) async fn write_meta<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    key: MessageGroupKey,
    order: &GroupOrder,
) -> Result<(), NetworkError> {
    let bytes = StoredOrder::of(order)
        .serialize_to_vector()
        .map_err(|err| io_error("encode an order", err))?;
    let _ = pers
        .store_byte_map_value(order.holder, NO_PEER, ORDERS, &group_id(key), bytes)
        .await
        .map_err(|err| io_error("store an order", err))?;
    Ok(())
}

/// Stores the entry at `seq` of `key`'s log under `holder`.
pub(crate) async fn append<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    holder: u64,
    key: MessageGroupKey,
    seq: u64,
    entry: &StoredEntry,
) -> Result<(), NetworkError> {
    let bytes = entry
        .serialize_to_vector()
        .map_err(|err| io_error("encode an entry", err))?;
    let _ = pers
        .store_byte_map_value(holder, NO_PEER, &log_map(key), &seq_key(seq), bytes)
        .await
        .map_err(|err| io_error("store an entry", err))?;
    Ok(())
}

/// `key`'s order as stored under `holder`, or `None` when nothing is (a group from before
/// numbering, which numbers from 1).
pub(crate) async fn load<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    holder: u64,
    key: MessageGroupKey,
) -> Result<Option<GroupOrder>, NetworkError> {
    let Some(meta) = pers
        .get_byte_map_value(holder, NO_PEER, ORDERS, &group_id(key))
        .await
        .map_err(|err| io_error("read an order", err))?
    else {
        return Ok(None);
    };
    let meta = StoredOrder::deserialize_from_vector(&meta)
        .map_err(|err| io_error("decode an order", err))?;
    let mut order = GroupOrder {
        holder,
        head: meta.reserved_through,
        reserved_through: meta.reserved_through,
        ..Default::default()
    };
    let Some(replay) = meta.replay else {
        return Ok(Some(order));
    };
    let mut stored: Vec<(u64, StoredEntry)> = pers
        .get_byte_map_values_by_key(holder, NO_PEER, &log_map(key))
        .await
        .map_err(|err| io_error("read a log", err))?
        .into_iter()
        .map(|(sub, bytes)| {
            let seq = sub
                .parse::<u64>()
                .map_err(|err| io_error("read a log", err))?;
            let entry = StoredEntry::deserialize_from_vector(&bytes)
                .map_err(|err| io_error("decode an entry", err))?;
            Ok((seq, entry))
        })
        .collect::<Result<_, NetworkError>>()?;
    stored.sort_by_key(|(seq, _)| *seq);
    stored.retain(|(seq, _)| *seq > replay.trimmed_through);
    let mut log = ReplayLog {
        since: replay.since,
        limits: Some(replay.limits),
        chain: replay.trimmed_chain,
        trimmed_through: replay.trimmed_through,
        trimmed_chain: replay.trimmed_chain,
        entries: Default::default(),
    };
    order.head = order.head.max(replay.trimmed_through).max(replay.since - 1);
    for (seq, entry) in stored {
        if let Some(id) = entry.id {
            let chain = Some(entry.chain);
            let _ = order
                .ids
                .insert(id, citadel_types::proto::GroupPosition { seq, chain });
        }
        log.chain = entry.chain;
        order.head = order.head.max(seq);
        log.entries.push_back(Entry {
            seq,
            bytes: entry.frame.len(),
            held_at_ns: entry.held_at_ns,
            chain: entry.chain,
            id: entry.id,
        });
    }
    order.replay = Some(log);
    Ok(Some(order))
}

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "group_log_tests.rs"]
mod tests;
