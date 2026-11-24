//! A replay group's log, at the server: started at creation or turned on later by the owner,
//! described to members ([`GroupOrderInfo`]), and read back for a fetch or a returning member.
//! Every function here takes the content of the node's group order lock
//! (`CitadelNodePeerLayer::group_order`) from its caller.

use super::group_log::write_meta;
use super::group_log_ops::read;
use super::group_log_plan::{Range, MAX_RANGE_ENTRIES};
use super::group_position::Positioned;
use super::group_sequencer::{GroupOrder, GroupOrderBook, ReplayLog};
use super::peer_layer::CitadelNodePeerLayer;
use crate::error::NetworkError;
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{
    GroupLogLimits, GroupMessageRefusal, GroupOrderInfo, GroupPosition, GroupReplayRefusal,
    MessageGroupKey, MessageGroupOptions,
};
use citadel_user::backend::PersistenceHandler;
use citadel_user::serialization::SyncIO;

/// What a read of a replay group's log found.
pub(crate) enum LogRead {
    /// The group keeps no log.
    NoReplay,
    /// Part of what was asked is older than the log keeps.
    Trimmed { earliest: u64, info: GroupOrderInfo },
    /// The positioned broadcasts, in order (at most [`MAX_RANGE_ENTRIES`]), and the order.
    Frames {
        frames: Vec<GroupBroadcast>,
        info: GroupOrderInfo,
    },
}

/// What a member is told of `order`, `joined` being its first readable position.
pub(crate) fn info_of(order: &GroupOrder, joined: Option<u64>) -> Option<GroupOrderInfo> {
    let log = order.replay.as_ref()?;
    Some(GroupOrderInfo {
        since: log.since,
        head: order.head,
        joined,
        limits: log.limits?,
    })
}

/// The limits a group asking for `asked` is held to on a server keeping at most `server`.
pub(crate) fn admitted(
    asked: GroupLogLimits,
    server: Option<GroupLogLimits>,
) -> Result<GroupLogLimits, GroupReplayRefusal> {
    let server = server.ok_or(GroupReplayRefusal::NotKept)?;
    asked.validate()?;
    let clamped = asked.clamped_to(&server);
    clamped.validate()?;
    Ok(clamped)
}

/// `key`'s order in `book`, which `load_group_order` put there.
pub(crate) fn loaded(
    book: &mut GroupOrderBook,
    key: MessageGroupKey,
) -> Result<&mut GroupOrder, NetworkError> {
    book.groups
        .get_mut(&key)
        .ok_or_else(|| NetworkError::msg(format!("{key:?} has no order loaded")))
}

/// As [`admitted`], for a group created with `options`: an ephemeral group keeps no log.
pub(crate) fn admitted_at_creation(
    options: &MessageGroupOptions,
    asked: GroupLogLimits,
    server: Option<GroupLogLimits>,
) -> Result<GroupLogLimits, GroupReplayRefusal> {
    if options.ephemeral {
        return Err(GroupReplayRefusal::NotApplicable);
    }
    admitted(asked, server)
}

impl<R: Ratchet> CitadelNodePeerLayer<R> {
    /// Whether `key` is ephemeral, and the log limits it was created with, already admitted
    /// (see [`admitted`]); `None` when there is no such group.
    async fn group_replay_option(
        &self,
        key: MessageGroupKey,
    ) -> Option<(bool, Option<GroupLogLimits>)> {
        let this = self.inner.read().await;
        let options = &this.message_groups.get(&key.cid)?.get(&key.mgid)?.options;
        Some((options.ephemeral, options.replay))
    }

    /// Starts `order`'s log at 1 when `key` was created with replay and nothing was numbered yet.
    pub(super) async fn seed_replay(
        &self,
        pers: &PersistenceHandler<R, R>,
        key: MessageGroupKey,
        order: &mut GroupOrder,
    ) -> Result<(), NetworkError> {
        if order.replay.is_some() || order.head != 0 {
            return Ok(());
        }
        let Some((_, Some(limits))) = self.group_replay_option(key).await else {
            return Ok(());
        };
        order.replay = Some(ReplayLog::starting_at(1, limits));
        write_meta(pers, key, order).await
    }

    /// Whether `key` keeps a log (a group that ended keeps none).
    pub(crate) async fn group_keeps_log(
        &self,
        book: &mut GroupOrderBook,
        key: MessageGroupKey,
    ) -> Result<bool, NetworkError> {
        if self.group_tree_and_owner(key).await.is_none() {
            return Ok(false);
        }
        let _ = self.load_group_order(book, key).await?;
        Ok(book.has_replay(key))
    }

    /// The refusal of a `bytes`-long message to `key` when the group keeps a log and the message
    /// is larger than the log takes (`GroupLogLimits::max_message_bytes`).
    pub(crate) async fn group_log_refuses(
        &self,
        book: &mut GroupOrderBook,
        key: MessageGroupKey,
        bytes: usize,
    ) -> Result<Option<GroupMessageRefusal>, NetworkError> {
        let _ = self.load_group_order(book, key).await?;
        let cap = loaded(book, key)?
            .replay
            .as_ref()
            .and_then(|log| log.limits)
            .map(|limits| limits.max_message_bytes);
        Ok(cap
            .filter(|max| bytes as u64 > u64::from(*max))
            .map(|max_bytes| GroupMessageRefusal::TooLarge {
                bytes: bytes as u64,
                max_bytes,
            }))
    }

    /// `key`'s order as a member is told it; `joined` for a joiner, whose first position is the
    /// next one.
    pub(crate) async fn group_order_info(
        &self,
        book: &mut GroupOrderBook,
        key: MessageGroupKey,
        joining: bool,
    ) -> Result<Option<GroupOrderInfo>, NetworkError> {
        let _ = self.load_group_order(book, key).await?;
        let order = loaded(book, key)?;
        Ok(info_of(order, joining.then_some(order.head + 1)))
    }

    /// Turns replay on for `key` at `owner`'s request, positioning the [`GroupBroadcast::ReplayEnabled`]
    /// that says so as the log's first entry. `Ok(Err(_))` when it is refused.
    pub(crate) async fn enable_group_replay(
        &self,
        book: &mut GroupOrderBook,
        key: MessageGroupKey,
        owner: u64,
        asked: GroupLogLimits,
        server: Option<GroupLogLimits>,
        now_ns: i64,
    ) -> Result<Result<(GroupBroadcast, GroupPosition), GroupReplayRefusal>, NetworkError> {
        let (recorded, pers) = self.load_group_order(book, key).await?;
        if recorded != owner {
            return Ok(Err(GroupReplayRefusal::NotTheOwner));
        }
        if self
            .group_replay_option(key)
            .await
            .is_none_or(|(ephemeral, _)| ephemeral)
        {
            return Ok(Err(GroupReplayRefusal::NotApplicable));
        }
        let limits = match admitted(asked, server) {
            Ok(limits) => limits,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let order = loaded(book, key)?;
        let Some(since) = order.enable_replay(limits) else {
            return Ok(Err(GroupReplayRefusal::NotApplicable));
        };
        write_meta(&pers, key, order).await?;
        let info = info_of(order, None)
            .filter(|info| info.since == since)
            .ok_or_else(|| NetworkError::msg("replay was turned on without a log"))?;
        let event = GroupBroadcast::ReplayEnabled { key, order: info };
        match self
            .position_group_broadcast(book, key, event, now_ns)
            .await?
        {
            Positioned::New { frame, position } => Ok(Ok((frame, position))),
            Positioned::Retry { .. } => Err(NetworkError::msg("an event is never a retry")),
        }
    }

    /// The positions `(after, until]` of `key`'s log, as members receive them.
    pub(crate) async fn read_group_log(
        &self,
        book: &mut GroupOrderBook,
        key: MessageGroupKey,
        after: u64,
        until: u64,
    ) -> Result<LogRead, NetworkError> {
        let (_, pers) = self.load_group_order(book, key).await?;
        let order = loaded(book, key)?;
        let (Some(log), Some(info)) = (order.replay.as_ref(), info_of(order, None)) else {
            return Ok(LogRead::NoReplay);
        };
        let seqs = match log.range(order.head, after, until, MAX_RANGE_ENTRIES) {
            Range::Trimmed { earliest } => return Ok(LogRead::Trimmed { earliest, info }),
            Range::Seqs(seqs) => seqs,
        };
        let mut frames = Vec::with_capacity(seqs.len());
        for (seq, entry) in seqs
            .iter()
            .zip(read(&pers, order.holder, key, &seqs).await?)
        {
            let frame = GroupBroadcast::deserialize_from_vector(&entry.frame)
                .map_err(|err| NetworkError::msg(format!("a stored broadcast: {err}")))?;
            frames.push(GroupBroadcast::Ordered {
                key,
                position: GroupPosition {
                    seq: *seq,
                    chain: Some(entry.chain),
                },
                frame: Box::new(frame),
            });
        }
        Ok(LogRead::Frames { frames, info })
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "group_replay_tests.rs"]
mod tests;
