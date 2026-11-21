/*!
# Group Channel Module

This module implements group communication channels in the Citadel Protocol, providing a secure and efficient way to manage group messaging and broadcasts.

## Features
- **Split Channel Architecture**: Separates send and receive operations for better control
- **Group Broadcast Support**: Enables efficient message broadcasting to group members
- **Permission Management**: Implements group owner privileges and member management
- **Secure Communication**: Uses SecBuffer for encrypted message payloads
- **Stream Interface**: Implements Stream trait for asynchronous message reception

## Core Components
- `GroupChannel`: Main channel type combining send and receive capabilities
- `GroupChannelSendHalf`: Handles message sending and group management operations
- `GroupChannelRecvHalf`: Manages message reception and implements Stream trait
- `GroupBroadcastPayload`: Represents different types of group messages

## Example Usage
```rust
use citadel_proto::prelude::*;
# async fn run() -> Result<(), Box<dyn std::error::Error>> {
# let group_channel: GroupChannel = todo!();
// Send a message to the group
group_channel.send_message(SecBuffer::from(b"Hello, world!" as &[u8])).await?;

let peer_cid = 1234;
// Invite new members
group_channel.invite(peer_cid).await?;

// Split the channel for separate send/receive handling
let (send_half, recv_half) = group_channel.split();
# }
```

## Important Notes
1. Channels can be split into send and receive halves for flexible usage
2. Group owners have special privileges for member management
3. Messages are encrypted using SecBuffer for security
4. Proper cleanup is handled through Drop implementations

## Related Components
- `peer_layer`: Manages peer-to-peer networking
- `packet_processor`: Handles packet processing and routing
- `session`: Manages connection sessions
- `message_group`: Implements group messaging logic

*/

use crate::error::NetworkError;
use crate::proto::outbound_sender::{send_from_sync, Sender, UnboundedReceiver};
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::proto::peer::group_owner::GroupOwner;
use crate::proto::remote::Ticket;
use crate::proto::session::{Group, SessionRequest};
use citadel_io::tokio_stream::StreamExt;
use citadel_io::{error, ErrorCode};
use citadel_types::crypto::SecBuffer;
use citadel_types::proto::MessageGroupKey;
use futures::Stream;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Debug)]
pub struct GroupChannel {
    send_half: GroupChannelSendHalf,
    recv_half: GroupChannelRecvHalf,
}

impl Deref for GroupChannel {
    type Target = GroupChannelSendHalf;

    fn deref(&self) -> &Self::Target {
        &self.send_half
    }
}

impl GroupChannel {
    pub fn new(
        tx: Sender<SessionRequest>,
        key: MessageGroupKey,
        ticket: Ticket,
        session_cid: u64,
        owner: GroupOwner,
        recv: UnboundedReceiver<GroupBroadcastPayload>,
    ) -> Self {
        let (undelivered_tx, undelivered) = citadel_io::tokio::sync::mpsc::unbounded_channel();
        Self {
            send_half: GroupChannelSendHalf {
                tx: tx.clone(),
                ticket,
                key,
                session_cid,
                owner,
                undelivered: undelivered_tx,
            },

            recv_half: GroupChannelRecvHalf {
                recv,
                tx,
                ticket,
                session_cid,
                key,
                undelivered,
            },
        }
    }

    /// Returns the group key of the channel
    pub fn key(&self) -> MessageGroupKey {
        self.recv_half.key
    }

    /// Receives the next element from the channel
    pub async fn recv(&mut self) -> Option<GroupBroadcastPayload> {
        self.recv_half.next().await
    }

    /// Splits the channel in two
    pub fn split(self) -> (GroupChannelSendHalf, GroupChannelRecvHalf) {
        (self.send_half, self.recv_half)
    }

    pub fn cid(&self) -> u64 {
        self.recv_half.session_cid
    }
}

#[derive(Debug)]
pub enum GroupBroadcastPayload {
    Message { payload: SecBuffer, sender: u64 },
    Event { payload: GroupBroadcast },
}

#[derive(Clone)]
pub struct GroupChannelSendHalf {
    tx: Sender<SessionRequest>,
    ticket: Ticket,
    key: MessageGroupKey,
    session_cid: u64,
    /// The group's owner, as the server last reported it.
    owner: GroupOwner,
    /// Where a message is reported undelivered once the session that carried it has ended.
    undelivered: citadel_io::tokio::sync::mpsc::UnboundedSender<GroupBroadcastPayload>,
}

impl Debug for GroupChannelSendHalf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GroupChannelTx {} connected to [{:?}]",
            self.session_cid, self.key
        )
    }
}

impl GroupChannelSendHalf {
    /// Broadcasts a message to the group
    pub async fn send_message(&self, message: SecBuffer) -> Result<(), NetworkError> {
        let sent = self
            .send_group_command(GroupBroadcast::Message {
                sender: self.session_cid,
                key: self.key,
                message,
            })
            .await;
        if sent.is_err() && self.tx.is_closed() {
            // The session has ended and released everything it held, so nothing will answer
            // the message: it is reported undelivered on this channel, as a live session reports
            // a message it cannot deliver.
            let refusal = GroupBroadcast::MessageResponse {
                key: self.key,
                delivery: citadel_types::proto::GroupDelivery::NotRelayed(
                    citadel_types::proto::NotRelayed::SessionEnded,
                ),
            };
            let _ = self.undelivered.send(refusal.into());
            return Ok(());
        }
        sent
    }

    /// The group's owner as the server last reported it: its creator until the owner leaves, then
    /// its successor. `None` once this channel has left the group.
    pub fn owner(&self) -> Option<u64> {
        self.owner.get()
    }

    /// Kicks a peer from the group. User must be owner
    pub async fn kick(&self, peer: u64) -> Result<(), NetworkError> {
        self.kick_all(vec![peer]).await
    }

    /// Kicks a set of peers from the group. User must be owner
    pub async fn kick_all<T: Into<Vec<u64>>>(&self, peers: T) -> Result<(), NetworkError> {
        self.permission_gate()?;
        self.send_group_command(GroupBroadcast::Kick {
            key: self.key,
            kick_list: peers.into(),
        })
        .await
    }

    /// Invites a single user to the group
    pub async fn invite(&self, peer_cid: u64) -> Result<(), NetworkError> {
        self.invite_all(vec![peer_cid]).await
    }

    /// Invites all listed members to the group
    pub async fn invite_all<T: Into<Vec<u64>>>(&self, peers: T) -> Result<(), NetworkError> {
        self.permission_gate()?;
        self.send_group_command(GroupBroadcast::Add {
            key: self.key,
            invitees: peers.into(),
        })
        .await
    }

    /// Assigns or raises a member to a command path in a `CommandHierarchy` group (owner only). The
    /// path is applied owner-locally and never sent to the relay; the member receives only a sealed
    /// node secret. Granting a path lets that member (and its superiors) read its subtree.
    pub async fn promote(
        &self,
        peer_cid: u64,
        path: citadel_types::proto::CommandPath,
    ) -> Result<(), NetworkError> {
        self.permission_gate()?;
        self.send_group_command(GroupBroadcast::Promote {
            key: self.key,
            target_cid: peer_cid,
            path,
        })
        .await
    }

    /// Revokes a member's elevated rank in a `CommandHierarchy` group (owner only). Rotates the
    /// hierarchy and epoch-bumps, so the demoted member can no longer read its former subtree's future
    /// traffic.
    pub async fn demote(&self, peer_cid: u64) -> Result<(), NetworkError> {
        self.permission_gate()?;
        self.send_group_command(GroupBroadcast::Demote {
            key: self.key,
            target_cid: peer_cid,
        })
        .await
    }

    /// Leaves the group
    pub async fn leave(&self) -> Result<(), NetworkError> {
        self.send_group_command(GroupBroadcast::LeaveRoom { key: self.key })
            .await
    }

    /// Ends the group
    pub async fn end(&self) -> Result<(), NetworkError> {
        self.permission_gate()?;
        self.send_group_command(GroupBroadcast::End { key: self.key })
            .await
    }

    async fn send_group_command(&self, broadcast: GroupBroadcast) -> Result<(), NetworkError> {
        self.tx
            .send(SessionRequest::Group(Group {
                ticket: self.ticket,
                broadcast,
            }))
            .await
            .map_err(|err| NetworkError::msg(err.to_string()))
    }

    fn permission_gate(&self) -> Result<(), NetworkError> {
        if self.owner.is(self.session_cid) {
            Ok(())
        } else {
            Err(error!(ErrorCode::PeerPermissionDenied))
        }
    }
}

pub struct GroupChannelRecvHalf {
    recv: UnboundedReceiver<GroupBroadcastPayload>,
    tx: Sender<SessionRequest>,
    ticket: Ticket,
    session_cid: u64,
    key: MessageGroupKey,
    undelivered: citadel_io::tokio::sync::mpsc::UnboundedReceiver<GroupBroadcastPayload>,
}

impl Debug for GroupChannelRecvHalf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GroupChannelRx: {} subscribed to {:?}",
            self.session_cid, self.key
        )
    }
}

impl Stream for GroupChannelRecvHalf {
    type Item = GroupBroadcastPayload;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(Some(undelivered)) = self.undelivered.poll_recv(cx) {
            return Poll::Ready(Some(undelivered));
        }
        match Pin::new(&mut self.recv).poll_recv(cx) {
            // The session's side has closed; what this channel itself reported still comes out.
            Poll::Ready(None) => Poll::Ready(self.undelivered.try_recv().ok()),
            polled => polled,
        }
    }
}

impl Drop for GroupChannelRecvHalf {
    fn drop(&mut self) {
        log::trace!(target: "citadel", "Dropping group channel recv half for {:?} | {:?}", self.session_cid, self.key);
        let request = SessionRequest::Group(Group {
            ticket: self.ticket,
            broadcast: GroupBroadcast::LeaveRoom { key: self.key },
        });

        // TODO: remove group channel locally on the inner process in state container
        if let Err(err) = send_from_sync(&self.tx, request) {
            log::warn!(target: "citadel", "Group channel drop warning: {err:?}")
        }
    }
}

#[cfg(test)]
#[path = "group_channel_drop_signal_tests.rs"]
mod drop_signal_tests;
