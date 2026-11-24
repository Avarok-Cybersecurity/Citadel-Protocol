//! The server's positioning of one group broadcast: the sequencer's decision
//! (`group_sequencer`), stored first (`group_log`), then committed, all with the node's group
//! order lock held, so the positions a group's members see are the order its fan-out writes them.

use super::group_log::{append, load, write_meta, StoredEntry};
use super::group_sequencer::{digest, GroupOrder, GroupOrderBook, Next, Persist};
use super::peer_layer::CitadelNodePeerLayer;
use crate::error::NetworkError;
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupPosition, MessageGroupKey};
use citadel_user::backend::PersistenceHandler;
use citadel_user::serialization::SyncIO;

/// The outcome of positioning one broadcast.
#[derive(Debug)]
pub(crate) enum Positioned {
    /// Fan `frame` (the broadcast inside [`GroupBroadcast::Ordered`]) out at `position`.
    New {
        frame: GroupBroadcast,
        position: GroupPosition,
    },
    /// The sender's message under this id was relayed already, at `position`: relay nothing.
    Retry { position: GroupPosition },
}

/// The group a broadcast is positioned in: its messages and Commits.
pub(crate) fn positioned_group(signal: &GroupBroadcast) -> Option<MessageGroupKey> {
    match signal {
        GroupBroadcast::Message { key, .. } | GroupBroadcast::Commit { key, .. } => Some(*key),
        _ => None,
    }
}

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    /// Positions `signal` in `key`. `book` is the content of [`Self::group_order`], locked by the
    /// caller until the positioned frame is written to every member's stream or backlog.
    pub(crate) async fn position_group_broadcast(
        &self,
        book: &mut GroupOrderBook,
        key: MessageGroupKey,
        signal: GroupBroadcast,
        now_ns: i64,
    ) -> Result<Positioned, NetworkError> {
        let (_, owner) = self
            .group_tree_and_owner(key)
            .await
            .ok_or_else(|| NetworkError::msg(format!("{key:?} ended before it was positioned")))?;
        let pers = { self.inner.read().await.persistence_handler.clone() };
        if let std::collections::hash_map::Entry::Vacant(unseen) = book.groups.entry(key) {
            let _ = unseen.insert(newest_stored(&pers, key).await?.unwrap_or_default());
        }
        held_by(book, key, owner);
        let id = match &signal {
            GroupBroadcast::Message { sender, id, .. } => Some((*sender, *id)),
            _ => None,
        };
        let bytes = signal
            .serialize_to_vector()
            .map_err(|err| NetworkError::msg(format!("unable to encode a broadcast: {err}")))?;
        let next = book.next(key, owner, id, &digest(&bytes));
        let position = match &next {
            Next::Retry { position } => {
                return Ok(Positioned::Retry {
                    position: *position,
                })
            }
            Next::New { position, persist } => {
                match persist {
                    Persist::Nothing => {}
                    Persist::Reserve(through) => {
                        let mut reserved = book.groups[&key].clone();
                        reserved.reserved_through = *through;
                        write_meta(&pers, key, &reserved).await?;
                    }
                    Persist::Log => {
                        let entry = StoredEntry {
                            held_at_ns: now_ns,
                            chain: position.chain.unwrap_or_default(),
                            id,
                            frame: bytes.clone(),
                        };
                        append(&pers, owner, key, position.seq, &entry).await?;
                    }
                }
                *position
            }
        };
        book.commit(key, &next, id, bytes.len(), now_ns);
        Ok(Positioned::New {
            frame: GroupBroadcast::Ordered {
                key,
                position,
                frame: Box::new(signal),
            },
            position,
        })
    }
}

/// Keeps `key`'s order under its current `owner`. When the owner changed, the next position
/// reserves a new block, which writes the order under the new owner before it is given. (A
/// replay group's log moves with its ownership instead; see `group_log`.)
fn held_by(book: &mut GroupOrderBook, key: MessageGroupKey, owner: u64) {
    if let Some(order) = book.groups.get_mut(&key) {
        if order.holder != owner && order.replay.is_none() {
            order.holder = owner;
            order.reserved_through = order.head;
        }
    }
}

/// `key`'s order as stored under any account, the furthest one: an order is written under the
/// group's owner, and a change of owner leaves the old one behind until the next block.
async fn newest_stored<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    key: MessageGroupKey,
) -> Result<Option<GroupOrder>, NetworkError> {
    let accounts = pers
        .get_clients_metadata(None)
        .await
        .map_err(|err| NetworkError::msg(format!("group order: unable to list accounts: {err}")))?;
    let mut newest: Option<GroupOrder> = None;
    for account in accounts {
        if let Some(order) = load(pers, account.cid, key).await? {
            if newest.as_ref().is_none_or(|kept| order.head > kept.head) {
                newest = Some(order);
            }
        }
    }
    Ok(newest)
}

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "group_position_tests.rs"]
mod tests;
