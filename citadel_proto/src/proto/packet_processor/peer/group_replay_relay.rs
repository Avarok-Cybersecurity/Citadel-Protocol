//! The server's side of a replay group (see `peer::group_replay`): replay turned on by the
//! owner, a member's fetch of a gap, and a returning member replayed from the last position it
//! holds.
//!
//! A returning member is replayed turn by turn, each turn at most `MAX_RANGE_ENTRIES` positions
//! read and written to its stream under the node's group order lock, which is released between
//! turns so other groups' traffic is not held up by one long replay. The order survives it: the
//! member stays away (unmarked as resumed) until the last turn, so whatever is positioned between
//! turns is not sent to it live but goes into the log, and a later turn reads it from there. The
//! last turn, which reaches the head, marks it resumed under the same lock, so nothing positioned
//! after the head it read can reach it before that turn's frames.

use super::group_broadcast::GroupBroadcast;
use super::group_restore::Reply;
use super::group_resume_relay::send_backlog;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_crafter;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::peer::group_log_plan::MAX_RANGE_ENTRIES;
use crate::proto::peer::group_replay::LogRead;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::{GroupLogLimits, GroupReplayRefusal, MessageGroupKey};

/// Server, on the owner's `EnableReplay`: the group keeps a log from the next position, and
/// every member is told so at that position. A refusal answers the owner alone.
pub(super) async fn enable<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    reply: Reply<'_, R>,
    owner: u64,
    key: MessageGroupKey,
    limits: GroupLogLimits,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let peer_layer = &session.hypernode_peer_layer;
    let manager = &session.session_manager;
    let Some((_, members)) = peer_layer.group_owner_and_members(key).await else {
        return reply.send(GroupBroadcast::ReplayRefused {
            key,
            refusal: GroupReplayRefusal::NotApplicable,
        });
    };
    let server = manager.server_load().and_then(|load| load.group_log);
    let mut book = peer_layer.group_order.clone().lock_owned().await;
    let now_ns = session.time_tracker.get_global_time_ns();
    let enabled = peer_layer
        .enable_group_replay(&mut book, key, owner, limits, server, now_ns)
        .await?;
    let (frame, position) = match enabled {
        Ok(positioned) => positioned,
        Err(refusal) => return reply.send(GroupBroadcast::ReplayRefused { key, refusal }),
    };
    log::info!(target: "citadel", "{owner} turned replay on for {key:?} from {}", position.seq);
    let len = members.len();
    let _ = manager
        .deliver_positioned(
            Some((key, position)),
            reply.timestamp,
            reply.ticket,
            members.into_iter().zip(std::iter::repeat_n(true, len)),
            true,
            frame,
            reply.security_level,
        )
        .await
        .map_err(NetworkError::msg)?;
    Ok(PrimaryProcessorResult::Void)
}

/// Server, on a member's `FetchRange`: the positions `(after, until]`, at most a page of them.
pub(super) async fn fetch<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    reply: Reply<'_, R>,
    member: u64,
    key: MessageGroupKey,
    after: u64,
    until: u64,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let peer_layer = &session.hypernode_peer_layer;
    let is_member = peer_layer
        .group_owner_and_members(key)
        .await
        .is_some_and(|(_, members)| members.contains(&member));
    let read = if is_member {
        let mut book = peer_layer.group_order.clone().lock_owned().await;
        peer_layer
            .read_group_log(&mut book, key, after, until)
            .await?
    } else {
        LogRead::NoReplay
    };
    reply.send(match read {
        LogRead::NoReplay => GroupBroadcast::ReplayRefused {
            key,
            refusal: GroupReplayRefusal::NotApplicable,
        },
        LogRead::Trimmed { earliest, info } => GroupBroadcast::Trimmed {
            key,
            earliest,
            order: info,
        },
        LogRead::Frames { frames, info } => GroupBroadcast::Range {
            key,
            head: info.head,
            frames,
        },
    })
}

/// Server, on `ResumeMembership`/`ResumeOwnership` from `member`'s own session for a group that
/// keeps a log: what was held for it before the log started, then the log after `after`, turn
/// by turn, then `Resumed`. `false` when the group keeps no log.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resume<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    sess_ratchet: &R,
    member: u64,
    key: MessageGroupKey,
    after: Option<u64>,
    ticket: Ticket,
    security_level: SecurityLevel,
) -> Result<bool, NetworkError> {
    let peer_layer = &session.hypernode_peer_layer;
    let send = |signal: &GroupBroadcast| -> Result<(), NetworkError> {
        let timestamp = session.time_tracker.get_global_time_ns();
        let packet = packet_crafter::peer_cmd::craft_group_message_packet(
            sess_ratchet,
            signal,
            ticket,
            C2S_IDENTITY_CID,
            timestamp,
            security_level,
        )?;
        session.send_to_primary_stream(Some(ticket), packet)
    };
    let mut cursor = after.unwrap_or_default();
    let mut first = true;
    loop {
        let mut book = peer_layer.group_order.clone().lock_owned().await;
        if std::mem::take(&mut first) {
            if !peer_layer.group_keeps_log(&mut book, key).await? {
                return Ok(false);
            }
            let Some((_, members)) = peer_layer.group_owner_and_members(key).await else {
                return Ok(true);
            };
            if !members.contains(&member) {
                log::warn!(target: "citadel", "Not resuming {key:?} for {member}: not a member");
                return Ok(true);
            }
            send_backlog(session, sess_ratchet, member, key, ticket, security_level).await?;
        }
        let (frames, info) = match peer_layer
            .read_group_log(&mut book, key, cursor, u64::MAX)
            .await?
        {
            LogRead::NoReplay => return Ok(false),
            LogRead::Trimmed { earliest, info } => {
                send(&GroupBroadcast::Trimmed {
                    key,
                    earliest,
                    order: info,
                })?;
                cursor = earliest.saturating_sub(1);
                continue;
            }
            LogRead::Frames { frames, info } => (frames, info),
        };
        let turn = frames.len();
        for frame in &frames {
            send(frame)?;
            if let GroupBroadcast::Ordered { position, .. } = frame {
                cursor = position.seq;
            }
        }
        if turn < MAX_RANGE_ENTRIES {
            if !peer_layer.mark_resumed(key, member).await {
                return Ok(true);
            }
            let (owner, members) =
                peer_layer
                    .group_owner_and_members(key)
                    .await
                    .ok_or_else(|| {
                        NetworkError::msg(format!("{key:?} ended while {member} resumed it"))
                    })?;
            send(&GroupBroadcast::Resumed {
                key,
                owner,
                members,
                order: Some(info),
            })?;
            return Ok(true);
        }
        drop(book);
        #[cfg(feature = "localhost-testing")]
        crate::test_hooks::group_replay_turn(key, turn).await;
    }
}
