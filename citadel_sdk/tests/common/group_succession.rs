//! Scaffolding for tests of who owns a group as its members leave: waiting for the server's word
//! on a channel or on the node's event stream.

use super::group::{Events, REJOIN_DEADLINE};
use citadel_io::tokio;
use citadel_sdk::prelude::*;

/// The next group event on `channel` that `pick` maps to a value; every other payload is logged.
pub async fn next_on_channel<T>(
    channel: &mut GroupChannel,
    what: &str,
    pick: impl Fn(&GroupBroadcast) -> Option<T>,
) -> T {
    tokio::time::timeout(REJOIN_DEADLINE, async {
        loop {
            match channel.recv().await {
                Some(GroupBroadcastPayload::Event { payload }) => match pick(&payload) {
                    Some(value) => return value,
                    None => {
                        log::info!(target: "citadel", "group event while waiting for {what}: {payload:?}")
                    }
                },
                Some(other) => {
                    log::info!(target: "citadel", "group payload while waiting for {what}: {other:?}")
                }
                None => panic!("group channel closed while waiting for {what}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {what} arrived within the deadline"))
}

/// The next group event on the node's event stream that `pick` maps to a value.
pub async fn next_group_event<T>(
    events: &mut Events,
    what: &str,
    pick: impl Fn(&GroupBroadcast) -> Option<T>,
) -> T {
    tokio::time::timeout(REJOIN_DEADLINE, async {
        loop {
            match events.recv().await {
                Some(NodeResult::GroupEvent(GroupEvent { event, .. })) => match pick(&event) {
                    Some(value) => return value,
                    None => log::info!(target: "citadel", "group event while waiting for {what}: {event:?}"),
                },
                Some(other) => {
                    log::info!(target: "citadel", "event while waiting for {what}: {other:?}")
                }
                None => panic!("event stream ended while waiting for {what}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {what} arrived within the deadline"))
}

/// Leaves the group of `channel` and returns whether the server says it left.
pub async fn leave(channel: &mut GroupChannel) -> Result<bool, NetworkError> {
    channel.leave().await?;
    Ok(
        next_on_channel(channel, "the answer to a leave", |event| match event {
            GroupBroadcast::LeaveRoomResponse { success, .. } => Some(*success),
            _ => None,
        })
        .await,
    )
}

/// The owner named by the next `OwnershipTransferred` on `channel`.
pub async fn ownership_transferred(channel: &mut GroupChannel) -> u64 {
    next_on_channel(channel, "OwnershipTransferred", |event| match event {
        GroupBroadcast::OwnershipTransferred { owner, .. } => Some(*owner),
        _ => None,
    })
    .await
}

/// Waits for the server's word that this member is out of the group of `channel`, and why.
pub async fn disconnected(channel: &mut GroupChannel) -> GroupEndReason {
    next_on_channel(channel, "Disconnected", |event| match event {
        GroupBroadcast::Disconnected { reason, .. } => Some(*reason),
        _ => None,
    })
    .await
}

/// Sends on `channel`, whose group this node is no longer in, and returns the server's answer,
/// which reaches the node's event stream.
pub async fn send_after_leaving(
    channel: &GroupChannel,
    events: &mut Events,
) -> Result<GroupDelivery, NetworkError> {
    channel
        .send_message(SecBuffer::from(b"after-close".to_vec()))
        .await?;
    Ok(
        next_group_event(events, "the answer to a send", |event| match event {
            GroupBroadcast::MessageResponse { delivery, .. } => Some(delivery.clone()),
            _ => None,
        })
        .await,
    )
}
