//! A client's answer when the server prompts it to restore a group (`RestoreMembership`,
//! `RestoreOwnership`): resume the state this node kept, else the state the server keeps sealed
//! for the account (`peer::group_backup`), else rejoin (a member) or found the tree afresh (the
//! owner).

use super::group_broadcast::{
    cgka_joiner_publish_key_package, cgka_owner_refound, create_group_channel, GroupBroadcast,
    JoinMode,
};
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_crafter;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::peer::group_cgka::GroupCgkaState;
use crate::proto::peer::{group_backup, group_state_store};
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::revfs_seal::RevfsKey;
use citadel_io::{error, ErrorCode};
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::MessageGroupKey;

/// What every answer here is sent with.
pub(super) struct Reply<'a, R: Ratchet> {
    pub sess_ratchet: &'a R,
    pub ticket: Ticket,
    pub timestamp: i64,
    pub security_level: SecurityLevel,
}

impl<R: Ratchet> Reply<'_, R> {
    pub fn send(&self, signal: GroupBroadcast) -> Result<PrimaryProcessorResult, NetworkError> {
        let packet = packet_crafter::peer_cmd::craft_group_message_packet(
            self.sess_ratchet,
            &signal,
            self.ticket,
            C2S_IDENTITY_CID,
            self.timestamp,
            self.security_level,
        )?;
        Ok(PrimaryProcessorResult::ReplyToSender(packet))
    }
}

fn session_cid<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
) -> Result<u64, NetworkError> {
    session
        .session_cid
        .get()
        .ok_or_else(|| error!(ErrorCode::StateImplicatedCidNotLoaded))
}

/// This account's key for the states the server keeps, if the application gave the node one.
fn account_key<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cid: u64,
) -> Option<RevfsKey> {
    let state = inner_state!(session.state_container);
    state.revfs_keys.as_ref()?.revfs_key(cid)
}

fn resume_signal(key: MessageGroupKey, as_owner: bool) -> GroupBroadcast {
    if as_owner {
        GroupBroadcast::ResumeOwnership { key }
    } else {
        GroupBroadcast::ResumeMembership { key }
    }
}

/// Makes `cgka` this session's state for `key` and opens the group's channel if it has none.
fn install<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    key: MessageGroupKey,
    cgka: GroupCgkaState,
) -> Result<(), NetworkError> {
    let channel_open = {
        let mut state = inner_mut_state!(session.state_container);
        let _ = state.group_cgka.insert(key, cgka);
        state.group_channels.contains_key(&key)
    };
    if !channel_open {
        let _ = create_group_channel(Ticket::default(), key, session)?;
    }
    Ok(())
}

/// Client, prompted to restore `key` on `tree`.
pub(super) async fn restore<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    reply: Reply<'_, R>,
    key: MessageGroupKey,
    tree: u64,
    as_owner: bool,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let cid = session_cid(session)?;
    let pers = session.account_manager.get_persistence_handler();
    let stored = group_state_store::load(pers, cid, key).await?;
    if let Some(cgka) = stored.filter(|cgka| cgka.tree == tree && cgka.is_owner() == as_owner) {
        log::info!(target: "citadel", "Resuming {key:?} from the state this node kept");
        install(session, key, cgka)?;
        return reply.send(resume_signal(key, as_owner));
    }
    if account_key(session, cid).is_some() {
        return reply.send(GroupBroadcast::FetchState { key });
    }
    start_over(session, reply, key, tree, as_owner)
}

/// Client, given the state the server keeps for it (`sealed`), on `tree`.
pub(super) fn kept<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    reply: Reply<'_, R>,
    key: MessageGroupKey,
    tree: u64,
    as_owner: bool,
    sealed: Option<Vec<u8>>,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let cid = session_cid(session)?;
    let opened = match (sealed, account_key(session, cid)) {
        (Some(sealed), Some(account_key)) => group_backup::open(&account_key, cid, key, &sealed)
            .and_then(|bytes| GroupCgkaState::import(&bytes))
            .map_err(|err| log::warn!(target: "citadel", "{err}"))
            .ok(),
        _ => None,
    };
    match opened.filter(|cgka| cgka.tree == tree && cgka.is_owner() == as_owner) {
        Some(cgka) => {
            log::info!(target: "citadel", "Resuming {key:?} from the state the server keeps for this account");
            install(session, key, cgka.restored_from_backup())?;
            reply.send(resume_signal(key, as_owner))
        }
        None => start_over(session, reply, key, tree, as_owner),
    }
}

/// No state to resume: a member rejoins with a fresh KeyPackage, the owner founds a new tree.
fn start_over<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    reply: Reply<'_, R>,
    key: MessageGroupKey,
    tree: u64,
    as_owner: bool,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let Reply {
        sess_ratchet,
        ticket,
        timestamp,
        security_level,
    } = reply;
    if as_owner {
        return cgka_owner_refound(
            session,
            sess_ratchet,
            key,
            tree,
            ticket,
            timestamp,
            security_level,
        );
    }
    let cid = session_cid(session)?;
    let published = cgka_joiner_publish_key_package(
        session,
        sess_ratchet,
        key,
        cid,
        ticket,
        timestamp,
        security_level,
        JoinMode::Replace,
    );
    if let Some(cgka) = inner_mut_state!(session.state_container)
        .group_cgka
        .get_mut(&key)
    {
        cgka.tree = tree;
    }
    published
}

/// Client, once the server has replayed what it held: a state that came from the server's sealed
/// copy has its leaf replaced now, so no other device of the account can follow the group on.
pub(super) fn resumed<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    reply: Reply<'_, R>,
    key: MessageGroupKey,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let cid = session_cid(session)?;
    let payload = {
        let mut state = inner_mut_state!(session.state_container);
        match state.group_cgka.get_mut(&key) {
            Some(cgka) if cgka.needs_new_leaf() && !cgka.is_owner() => {
                cgka.new_leaf_key_package(cid)?
            }
            _ => return Ok(PrimaryProcessorResult::Void),
        }
    };
    log::info!(target: "citadel", "Replacing this member's leaf in {key:?}");
    reply.send(GroupBroadcast::KeyPackage {
        key,
        joiner_cid: cid,
        payload,
    })
}
