//! How a broadcast joiner waits for its owner's group to exist before asking to join it.
use crate::prelude::*;
use futures::StreamExt;
use uuid::Uuid;

/// Returns once the owner's group `key` exists, or fails with `BroadcastOwnerGroupMissing`.
pub(crate) async fn wait_for_owner_group<R: Ratchet>(
    connect_success: &CitadelClientServerConnection<R>,
    owner: &MutualPeer,
    group_id: Uuid,
    key: MessageGroupKey,
) -> Result<(), NetworkError> {
    await_group(connect_success, owner, group_id, key).await
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
