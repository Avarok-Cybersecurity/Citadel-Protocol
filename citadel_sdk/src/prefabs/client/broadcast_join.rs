//! How a broadcast joiner waits for its owner's group to exist before asking to join it.
use crate::prelude::*;
use citadel_proto::constants::{protocol_version_at_least, AWAIT_GROUP_SINCE};
use futures::StreamExt;
use uuid::Uuid;

/// Which wait a joiner uses, decided by the server's protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JoinWait {
    /// Send [`GroupBroadcast::AwaitGroup`]; the server answers once the group exists.
    AwaitGroup,
    /// Legacy compat: sleep-poll the owner's groups. Kept only for servers that predate
    /// [`AWAIT_GROUP_SINCE`] (or whose version is unknown), which cannot decode `AwaitGroup`
    /// and would leave the joiner waiting forever.
    LegacyPoll,
}

impl JoinWait {
    pub(crate) fn for_server(server_protocol_version: Option<u32>) -> Self {
        if protocol_version_at_least(server_protocol_version, AWAIT_GROUP_SINCE) {
            Self::AwaitGroup
        } else {
            Self::LegacyPoll
        }
    }
}

/// Returns once the owner's group `key` exists, or fails with `BroadcastOwnerGroupMissing`.
pub(crate) async fn wait_for_owner_group<R: Ratchet>(
    connect_success: &CitadelClientServerConnection<R>,
    local_user: &UserIdentifier,
    owner: &MutualPeer,
    group_id: Uuid,
    key: MessageGroupKey,
) -> Result<(), NetworkError> {
    let server_protocol_version = connect_success
        .channel
        .as_ref()
        .and_then(PeerChannel::peer_protocol_version);
    match JoinWait::for_server(server_protocol_version) {
        JoinWait::AwaitGroup => await_group(connect_success, owner, group_id, key).await,
        JoinWait::LegacyPoll => {
            log::warn!(target: "citadel", "broadcast: server protocol version {server_protocol_version:?} predates AwaitGroup; polling for {key:?}");
            legacy_poll(connect_success, local_user, owner, group_id, key).await
        }
    }
}

fn owner_group_missing(owner: &MutualPeer, group_id: Uuid) -> NetworkError {
    citadel_io::error!(
        citadel_io::ErrorCode::BroadcastOwnerGroupMissing,
        citadel_io::Dbg(owner.clone()),
        citadel_io::Dbg(group_id)
    )
}

/// The server answers once the owner's group exists: now, or when the owner creates it.
/// No deadline is imposed here; the owner may create it at any time.
async fn await_group<R: Ratchet>(
    connect_success: &CitadelClientServerConnection<R>,
    owner: &MutualPeer,
    group_id: Uuid,
    key: MessageGroupKey,
) -> Result<(), NetworkError> {
    let mut watch = connect_success
        .send_callback_subscription(NodeRequest::GroupBroadcastCommand(GroupBroadcastCommand {
            session_cid: connect_success.cid,
            command: GroupBroadcast::AwaitGroup { key },
        }))
        .await?;
    loop {
        let event = watch
            .next()
            .await
            .map(|evt| evt.into_result())
            .transpose()?;
        match event {
            Some(NodeResult::GroupEvent(GroupEvent {
                event: GroupBroadcast::GroupAvailable { key: available },
                ..
            })) if available == key => return Ok(()),
            Some(NodeResult::GroupEvent(GroupEvent {
                event: GroupBroadcast::GroupNonExists { .. },
                ..
            }))
            | None => return Err(owner_group_missing(owner, group_id)),
            Some(_) => {}
        }
    }
}

/// Legacy compat, for servers below [`AWAIT_GROUP_SINCE`] only: exponential backoff over the
/// owner's groups, giving up after five polls.
async fn legacy_poll<R: Ratchet>(
    connect_success: &CitadelClientServerConnection<R>,
    local_user: &UserIdentifier,
    owner: &MutualPeer,
    group_id: Uuid,
    key: MessageGroupKey,
) -> Result<(), NetworkError> {
    let group_owner_handle = connect_success
        .propose_target(local_user.clone(), owner.cid)
        .await?;
    for retries in 0..=4u32 {
        if group_owner_handle.list_owned_groups().await?.contains(&key) {
            return Ok(());
        }
        citadel_io::time::sleep(std::time::Duration::from_secs(2u64.pow(retries))).await;
    }
    Err(owner_group_missing(owner, group_id))
}

#[cfg(test)]
mod tests {
    use super::JoinWait;
    use citadel_proto::constants::PROTOCOL_VERSION;
    use embedded_semver::Semver;

    fn version(major: usize, minor: usize, patch: usize) -> Option<u32> {
        Some(Semver::new(major, minor, patch).to_u32().unwrap())
    }

    #[test]
    fn a_current_server_is_sent_await_group() {
        assert_eq!(
            JoinWait::for_server(Some(*PROTOCOL_VERSION)),
            JoinWait::AwaitGroup
        );
        assert_eq!(
            JoinWait::for_server(version(0, 11, 0)),
            JoinWait::AwaitGroup
        );
    }

    #[test]
    fn an_old_or_unknown_server_gets_the_legacy_poll() {
        assert_eq!(
            JoinWait::for_server(version(0, 10, 0)),
            JoinWait::LegacyPoll
        );
        assert_eq!(
            JoinWait::for_server(version(0, 10, 1)),
            JoinWait::LegacyPoll
        );
        assert_eq!(JoinWait::for_server(None), JoinWait::LegacyPoll);
        assert_eq!(JoinWait::for_server(Some(u32::MAX)), JoinWait::LegacyPoll);
    }
}
