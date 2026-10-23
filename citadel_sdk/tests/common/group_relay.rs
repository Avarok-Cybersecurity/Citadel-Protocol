//! Scaffolding for tests of a group's relay options (ephemeral delivery, message limits): a
//! server whose remote the clients can query, and a pair of nodes in one group.

use super::group::*;
use citadel_io::tokio;
use citadel_sdk::prelude::*;
use citadel_sdk::test_common::{server_test_node, wait_for_peers};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

pub type ServerRemote = Arc<OnceLock<NodeRemote<StackedRatchet>>>;

/// A server, and the slot its remote is put in once it starts.
pub fn probed_server() -> (
    NodeFuture<'static, impl NetKernel<StackedRatchet>>,
    SocketAddr,
    ServerRemote,
) {
    let slot: ServerRemote = Arc::new(OnceLock::new());
    let kernel = {
        let slot = slot.clone();
        GroupTestKernel::new(
            move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                let _ = slot.set(remote);
                Ok(())
            },
        )
    };
    let (server, addr) = server_test_node(kernel, |_| {});
    (server, addr, slot)
}

pub fn server_of(slot: &ServerRemote) -> &NodeRemote<StackedRatchet> {
    slot.get().expect("the server started before any client")
}

/// The group messages for `key` the server holds in `member`'s mailbox.
pub async fn mailed_group_messages(
    server: &NodeRemote<StackedRatchet>,
    member: u64,
    key: MessageGroupKey,
) -> usize {
    let mailbox = server
        .account_manager()
        .get_persistence_handler()
        .get_byte_map_values_by_key(member, 0, PEER_MAILBOX_MAP)
        .await
        .expect("the server's mailbox is readable");
    mailbox
        .values()
        .filter(|bytes| {
            matches!(
                PeerSignal::deserialize_from_vector(bytes),
                Ok(PeerSignal::BroadcastConnected {
                    group_broadcast: GroupBroadcast::Message { key: mailed, .. },
                    ..
                }) if mailed == key
            )
        })
        .count()
}

/// Waits until the server holds no session for `cid`.
pub async fn until_offline(server: &NodeRemote<StackedRatchet>, cid: u64) {
    tokio::time::timeout(REJOIN_DEADLINE, async {
        while server
            .sessions()
            .await
            .expect("the server lists its sessions")
            .sessions
            .iter()
            .any(|session| session.cid == cid)
        {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the member's session never ended at the server")
}

/// The server's answer to the next message sent on `channel`.
pub async fn next_send_answer(channel: &mut GroupChannel) -> GroupBroadcast {
    tokio::time::timeout(REJOIN_DEADLINE, async {
        loop {
            match channel.recv().await {
                Some(GroupBroadcastPayload::Event {
                    payload:
                        answer @ (GroupBroadcast::MessageResponse { .. }
                        | GroupBroadcast::MessageRefused { .. }),
                }) => return answer,
                Some(other) => {
                    log::info!(target: "citadel", "group payload while waiting for a send's answer: {other:?}")
                }
                None => panic!("group channel closed while waiting for a send's answer"),
            }
        }
    })
    .await
    .expect("the server never answered the send")
}

/// Owner side: register, befriend `member`, and open a group with `options` inviting it. Returns
/// once the member's channel is open (the member calls [`join_group`]).
pub async fn open_group(
    remote: &NodeRemote<StackedRatchet>,
    server_addr: SocketAddr,
    (me, member): (&str, &str),
    options: MessageGroupOptions,
) -> Result<(CitadelClientServerConnection<StackedRatchet>, GroupChannel), NetworkError> {
    let conn = register_connect_and_befriend(remote, server_addr, me, member).await?;
    let channel = conn
        .create_group_with_options(Some(vec![member.to_string().into()]), options)
        .await?;
    wait_for_peers().await;
    Ok((conn, channel))
}

/// Member side of [`open_group`].
pub async fn join_group(
    remote: &NodeRemote<StackedRatchet>,
    server_addr: SocketAddr,
    (me, owner): (&str, &str),
    events: &mut Events,
) -> Result<(CitadelClientServerConnection<StackedRatchet>, GroupChannel), NetworkError> {
    let conn = register_connect_and_befriend(remote, server_addr, me, owner).await?;
    let invitation = next_invitation(events).await;
    let _ = responses::group_invite(invitation, true, remote).await?;
    let channel = next_group_channel(events, me).await;
    wait_for_peers().await;
    Ok((conn, channel))
}
