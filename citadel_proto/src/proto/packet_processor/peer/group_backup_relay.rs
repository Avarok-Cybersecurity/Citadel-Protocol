//! The server's side of the sealed group states it keeps for members (see `peer::group_backup`):
//! it stores a member's sealed state, within the group mail byte cap, and hands it back to the
//! member's own session. It cannot open either.

use super::group_broadcast::GroupBroadcast;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::peer::group_backup::GROUP_BACKUP_MAP;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::MessageGroupKey;

/// Server, on `KeepState` from `member`'s session: keeps `sealed` in place of its last.
pub(crate) async fn keep<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    member: u64,
    key: MessageGroupKey,
    sealed: Vec<u8>,
) -> Result<(), NetworkError> {
    if session
        .hypernode_peer_layer
        .tree_of_member(key, member)
        .await
        .is_none()
    {
        log::warn!(target: "citadel", "Not keeping a state of {key:?} for {member}: not a member");
        return Ok(());
    }
    let cap = session
        .session_manager
        .server_load()
        .map(|load| load.limits.group_mail.max_bytes.get())
        .ok_or_else(|| NetworkError::msg("only a server keeps group states"))?;
    if sealed.len() > cap {
        log::warn!(target: "citadel", "Not keeping a state of {key:?} for {member}: {} bytes is over the {cap}-byte cap", sealed.len());
        return Ok(());
    }
    let pers = session.account_manager.get_persistence_handler();
    let _ = pers
        .store_byte_map_value(
            member,
            key.cid,
            GROUP_BACKUP_MAP,
            &key.mgid.to_string(),
            sealed,
        )
        .await?;
    Ok(())
}

/// Server, on `FetchState` from `member`'s session: the state it keeps for the member, with the
/// group's tree and its recorded owner. A non-member's kept state is dropped and none is returned.
pub(crate) async fn fetch<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    member: u64,
    key: MessageGroupKey,
) -> Result<Option<GroupBroadcast>, NetworkError> {
    let pers = session.account_manager.get_persistence_handler();
    let sub_key = key.mgid.to_string();
    let peer_layer = &session.hypernode_peer_layer;
    let (Some(tree), Some(owner)) = (
        peer_layer.tree_of_member(key, member).await,
        peer_layer.group_owner(key).await,
    ) else {
        let _ = pers
            .remove_byte_map_value(member, key.cid, GROUP_BACKUP_MAP, &sub_key)
            .await?;
        return Ok(None);
    };
    let sealed = pers
        .get_byte_map_value(member, key.cid, GROUP_BACKUP_MAP, &sub_key)
        .await?;
    Ok(Some(GroupBroadcast::KeptState {
        key,
        tree,
        owner,
        sealed,
    }))
}
