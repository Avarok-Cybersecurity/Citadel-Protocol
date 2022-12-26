use crate::error::NetworkError;
use crate::prelude::{MessageGroupKey, SecBuffer};
use crate::proto::outbound_sender::{Sender, UnboundedReceiver};
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::proto::remote::{NodeRemote, Ticket};
use crate::proto::session::SessionRequest;
use citadel_user::re_imports::__private::Formatter;
use futures::Stream;
use std::fmt::Debug;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_stream::StreamExt;

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
        node_remote: NodeRemote,
        tx: Sender<SessionRequest>,
        key: MessageGroupKey,
        ticket: Ticket,
        implicated_cid: u64,
        recv: UnboundedReceiver<GroupBroadcastPayload>,
    ) -> Self {
        Self {
            send_half: GroupChannelSendHalf {
                node_remote,
                tx: tx.clone(),
                ticket,
                key,
                implicated_cid,
            },

            recv_half: GroupChannelRecvHalf {
                recv,
                tx,
                ticket,
                implicated_cid,
                key,
            },
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
    Event { payload: GroupBroadcast },
}

pub struct GroupChannelSendHalf {
    #[allow(dead_code)]
    node_remote: NodeRemote,
    tx: Sender<SessionRequest>,
    ticket: Ticket,
    key: MessageGroupKey,
    implicated_cid: u64,
}

impl Debug for GroupChannelSendHalf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GroupChannelTx {} connected to [{:?}]",
            self.implicated_cid, self.key
        )
    }
}

impl GroupChannelSendHalf {
    /// Broadcasts a message to the group
    pub async fn send_message(&self, message: SecBuffer) -> Result<(), NetworkError> {
        self.send_group_command(GroupBroadcast::Message(
            self.implicated_cid,
            self.key,
            message,
        ))
        .await
    }

    /// Kicks a peer from the group. User must be owner
    pub async fn kick(&self, peer: u64) -> Result<(), NetworkError> {
        self.kick_all(vec![peer]).await
    }

    /// Kicks a set of peers from the group. User must be owner
    pub async fn kick_all<T: Into<Vec<u64>>>(&self, peers: T) -> Result<(), NetworkError> {
        self.permission_gate()?;
        self.send_group_command(GroupBroadcast::Kick(self.key, peers.into()))
            .await
    }

    /// Invites a single user to the group
    pub async fn invite(&self, peer_cid: u64) -> Result<(), NetworkError> {
        self.invite_all(vec![peer_cid]).await
    }

    /// Invites all listed members to the group
    pub async fn invite_all<T: Into<Vec<u64>>>(&self, peers: T) -> Result<(), NetworkError> {
        self.permission_gate()?;
        self.send_group_command(GroupBroadcast::Add(self.key, peers.into()))
            .await
    }

    async fn send_group_command(&self, broadcast: GroupBroadcast) -> Result<(), NetworkError> {
        self.tx
            .send(SessionRequest::Group {
                ticket: self.ticket,
                broadcast,
            })
            .await
            .map_err(|err| NetworkError::msg(err.to_string()))
    }

    fn permission_gate(&self) -> Result<(), NetworkError> {
        if self.implicated_cid == self.key.cid {
            Ok(())
        } else {
            Err(NetworkError::InvalidRequest(
                "User does not have permissions to make this call",
            ))
        }
    }
}

pub struct GroupChannelRecvHalf {
    recv: UnboundedReceiver<GroupBroadcastPayload>,
    tx: Sender<SessionRequest>,
    ticket: Ticket,
    implicated_cid: u64,
    key: MessageGroupKey,
}

impl Debug for GroupChannelRecvHalf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GroupChannelRx: {} subscribed to {:?}",
            self.implicated_cid, self.key
        )
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
        log::trace!(target: "citadel", "Dropping group channel recv half for {:?} | {:?}", self.implicated_cid, self.key);
        let request = SessionRequest::Group {
            ticket: self.ticket,
            broadcast: GroupBroadcast::LeaveRoom(self.key),
        };

        // TODO: remove group channel locally on the inner process in state container
        if let Err(err) = self.tx.try_send(request) {
            log::warn!(target: "citadel", "Group channel drop warning: {:?}", err)
        }
    }
}
