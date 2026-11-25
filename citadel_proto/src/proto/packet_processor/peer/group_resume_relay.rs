//! The server's side of a member's return to its group (see `peer::group_resume`): the replay
//! of what it held, the Welcome that brings a rejoining member back, and an owner's new tree.

use super::group_broadcast::GroupBroadcast;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_crafter;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::peer::group_mail;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::MessageGroupKey;

/// `member`'s backlog for `key`, read but kept: what was held while it was away, in the group's
/// order.
async fn held_backlog<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    member: u64,
    key: MessageGroupKey,
) -> Result<group_mail::Held, NetworkError> {
    let limits = session
        .session_manager
        .server_load()
        .map(|load| load.group_mail)
        .ok_or_else(|| NetworkError::msg("only a server holds group mail"))?;
    let retention = session.hypernode_peer_layer.group_retention(key).await;
    let pers = session.account_manager.get_persistence_handler();
    let now_ns = session.time_tracker.get_global_time_ns();
    group_mail::held(pers, member, key, limits.max_age_for(retention), now_ns).await
}

/// Removes `member`'s backlog for `key` unsent.
async fn drop_backlog<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    member: u64,
    key: MessageGroupKey,
) -> Result<(), NetworkError> {
    let held = held_backlog(session, member, key).await?;
    let pers = session.account_manager.get_persistence_handler();
    group_mail::forget(pers, member, key, &held.sub_keys).await
}

/// Server, on `ResumeMembership`/`ResumeOwnership` from `member`'s own session: replay its
/// backlog on this session, mark the end of it (`Resumed`), then send it the group live.
pub(crate) async fn resume<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    sess_ratchet: &R,
    member: u64,
    key: MessageGroupKey,
    ticket: Ticket,
    security_level: SecurityLevel,
) -> Result<(), NetworkError> {
    let peer_layer = &session.hypernode_peer_layer;
    let _ordered = peer_layer.group_order.clone().lock_owned().await;
    if !peer_layer.mark_resumed(key, member).await {
        log::warn!(target: "citadel", "Not resuming {key:?} for {member}: not a member");
        return Ok(());
    }
    send_backlog(session, sess_ratchet, member, key, ticket, security_level).await?;
    let timestamp = session.time_tracker.get_global_time_ns();
    let (owner, members) = peer_layer
        .group_owner_and_members(key)
        .await
        .ok_or_else(|| NetworkError::msg(format!("{key:?} ended while {member} resumed it")))?;
    let resumed = packet_crafter::peer_cmd::craft_group_message_packet(
        sess_ratchet,
        &GroupBroadcast::Resumed {
            key,
            owner,
            members,
            order: None,
        },
        ticket,
        C2S_IDENTITY_CID,
        timestamp,
        security_level,
    )?;
    session.send_to_primary_stream(Some(ticket), resumed)
}

/// Server: sends `member` its backlog for `key` on this session, in the group's order, and
/// removes it once handed to the stream. A replay cut short leaves it held, and the member's
/// node delivers a position it already has at most once (`group_delivered`).
pub(super) async fn send_backlog<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    sess_ratchet: &R,
    member: u64,
    key: MessageGroupKey,
    ticket: Ticket,
    security_level: SecurityLevel,
) -> Result<(), NetworkError> {
    let backlog = held_backlog(session, member, key).await?;
    log::info!(target: "citadel", "Resuming {key:?} for {member}: replaying {} held broadcast(s)", backlog.signals.len());
    let timestamp = session.time_tracker.get_global_time_ns();
    for signal in &backlog.signals {
        let packet = packet_crafter::peer_cmd::craft_group_message_packet(
            sess_ratchet,
            signal,
            ticket,
            C2S_IDENTITY_CID,
            timestamp,
            security_level,
        )?;
        session.send_to_primary_stream(Some(ticket), packet)?;
    }
    let pers = session.account_manager.get_persistence_handler();
    group_mail::forget(pers, member, key, &backlog.sub_keys).await
}

/// Server, once a Welcome for `joiner` is relayed: the joiner is in the group from here on, and
/// what was held for it before cannot be opened by the state the Welcome founds.
pub(crate) async fn welcomed<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    joiner: u64,
    key: MessageGroupKey,
) {
    if !session.hypernode_peer_layer.mark_resumed(key, joiner).await {
        return;
    }
    if let Err(err) = drop_backlog(session, joiner, key).await {
        log::warn!(target: "citadel", "Unable to drop the backlog of {key:?} for {joiner}: {err}");
    }
}

/// Server, on the owner's `RestoreOwnership` echo: the owner founded a new tree. Every member's
/// backlog was sealed under the old one, so it is dropped, and each member is prompted to rejoin.
pub(crate) async fn refounded<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    key: MessageGroupKey,
    ticket: Ticket,
    timestamp: i64,
    security_level: SecurityLevel,
) {
    let peer_layer = &session.hypernode_peer_layer;
    let _ordered = peer_layer.group_order.clone().lock_owned().await;
    let Some((tree, owner, members)) = peer_layer.refound_tree(key).await else {
        return;
    };
    for member in &members {
        if let Err(err) = drop_backlog(session, *member, key).await {
            log::warn!(target: "citadel", "Unable to drop the backlog of {key:?} for {member}: {err}");
        }
    }
    let len = members.len();
    log::info!(target: "citadel", "Owner re-founded {key:?} (tree {tree}); prompting {len} member(s) to rejoin");
    if let Err(err) = session
        .session_manager
        .send_group_broadcast_signal_to(
            timestamp,
            ticket,
            members.into_iter().zip(std::iter::repeat_n(true, len)),
            false,
            GroupBroadcast::RestoreMembership { key, tree, owner },
            security_level,
        )
        .await
    {
        log::error!(target: "citadel", "Unable to prompt the members of {key:?} to rejoin: {err}");
    }
}
