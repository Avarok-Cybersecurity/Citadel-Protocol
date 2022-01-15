use crate::prelude::{SecBuffer, Ticket, MessageGroupKey};
use crate::hdp::state_container::StateContainer;
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use crate::hdp::hdp_packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::error::NetworkError;
use std::fmt::Debug;
use hyxe_user::re_imports::__private::Formatter;
use crate::hdp::outbound_sender::UnboundedReceiver;
use std::ops::Deref;
use tokio_stream::StreamExt;

#[derive(Debug)]
pub struct GroupChannel {
    send_half: GroupChannelSendHalf,
    recv_half: GroupChannelRecvHalf
}

impl Deref for GroupChannel {
    type Target = GroupChannelSendHalf;

    fn deref(&self) -> &Self::Target {
        &self.send_half
    }
}

impl GroupChannel {
    pub fn new(state_container: StateContainer, key: MessageGroupKey, ticket: Ticket, implicated_cid: u64, recv: UnboundedReceiver<GroupBroadcastPayload>) -> Self {
        Self {
            send_half: GroupChannelSendHalf {
                state_container: state_container.clone(),
                ticket,
                key,
                implicated_cid
            },

            recv_half: GroupChannelRecvHalf {
                recv,
                state_container,
                ticket,
                implicated_cid,
                key
            }
        }
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
        self.recv_half.implicated_cid
    }
}

#[derive(Debug)]
pub enum GroupBroadcastPayload {
    Message { payload: SecBuffer, sender: u64 },
    Event { payload: GroupBroadcast }
}

pub struct GroupChannelSendHalf {
    state_container: StateContainer,
    ticket: Ticket,
    key: MessageGroupKey,
    implicated_cid: u64
}

impl Debug for GroupChannelSendHalf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GroupChannelTx {} connected to [{:?}]", self.implicated_cid, self.key)
    }
}

impl GroupChannelSendHalf {
    /// Broadcasts a message to the group
    pub async fn send_message(&self, message: SecBuffer) -> Result<(), NetworkError> {
        inner_mut_state!(self.state_container).process_outbound_broadcast_command(self.ticket, GroupBroadcast::Message(self.implicated_cid, self.key,  message))?;
        // This allows yielding when this function is called in a for loop
        tokio::task::yield_now().await;
        Ok(())
    }

    /// Kicks a peer from the group. User must be owner
    pub fn kick(&self, peer: u64) -> Result<(), NetworkError> {
        self.kick_all(vec![peer])
    }

    /// Kicks a set of peers from the group. User must be owner
    pub fn kick_all<T: Into<Vec<u64>>>(&self, peers: T) -> Result<(), NetworkError> {
        self.permission_gate()?;
        self.send_group_command(GroupBroadcast::Kick(self.key, peers.into()))
    }

    /// Invites a single user to the group
    pub fn invite(&self, peer_cid: u64) -> Result<(), NetworkError> {
        self.invite_all(vec![peer_cid])
    }

    /// Invites all listed members to the group
    pub fn invite_all<T: Into<Vec<u64>>>(&self, peers: T) -> Result<(), NetworkError> {
        self.permission_gate()?;
        self.send_group_command(GroupBroadcast::Add(self.key, peers.into()))
    }

    fn send_group_command(&self, command: GroupBroadcast) -> Result<(), NetworkError> {
        inner_mut_state!(self.state_container).process_outbound_broadcast_command(self.ticket, command)
    }

    fn permission_gate(&self) -> Result<(), NetworkError> {
        if self.implicated_cid == self.key.cid {
            Ok(())
        } else {
            Err(NetworkError::InvalidRequest("User does not have permissions to make this call"))
        }
    }
}

pub struct GroupChannelRecvHalf {
    recv: UnboundedReceiver<GroupBroadcastPayload>,
    state_container: StateContainer,
    ticket: Ticket,
    implicated_cid: u64,
    key: MessageGroupKey
}

impl Debug for GroupChannelRecvHalf {
    fn fmt(&self, f: &mut Formatter<'_>) -> hyxe_user::re_imports::__private::fmt::Result {
        write!(f, "GroupChannelRx: {} subscribed to {:?}", self.implicated_cid, self.key)
    }
}

impl Stream for GroupChannelRecvHalf {
    type Item = GroupBroadcastPayload;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.recv).poll_recv(cx)
    }
}

impl Drop for GroupChannelRecvHalf {
    fn drop(&mut self) {
        if let Err(err) = inner_mut_state!(self.state_container).process_outbound_broadcast_command(self.ticket, GroupBroadcast::LeaveRoom(self.key)) {
            log::warn!("Drop error: {:?}", err)
        }
    }
}