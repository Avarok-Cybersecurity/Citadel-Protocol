use crate::error::NetworkError;
use crate::kernel::kernel_communicator::{KernelAsyncCallbackHandler, KernelStreamSubscription};
use crate::prelude::{NodeRequest, NodeResult};
use crate::proto::node::HdpServerRemoteInner;
use crate::proto::outbound_sender::BoundedSender;
use citadel_user::account_manager::AccountManager;
use citadel_wire::hypernode_type::NodeType;
use futures::channel::mpsc::TrySendError;
use futures::{Sink, SinkExt};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// allows convenient communication with the server
#[derive(Clone)]
pub struct NodeRemote {
    outbound_send_request_tx: BoundedSender<(NodeRequest, Ticket)>,
    inner: Arc<HdpServerRemoteInner>,
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Box, &mut)]
pub trait Remote: Clone + Send {
    async fn send(&mut self, request: NodeRequest) -> Result<Ticket, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_with_custom_ticket(ticket, request)
            .await
            .map(|_| ticket)
    }

    async fn send_with_custom_ticket(
        &mut self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), NetworkError>;
    async fn send_callback_subscription(
        &mut self,
        request: NodeRequest,
    ) -> Result<KernelStreamSubscription, NetworkError>;
    async fn send_callback(&mut self, request: NodeRequest) -> Result<NodeResult, NetworkError>;
    fn account_manager(&self) -> &AccountManager;
    fn get_next_ticket(&self) -> Ticket;
}

#[async_trait::async_trait]
impl Remote for NodeRemote {
    async fn send(&mut self, request: NodeRequest) -> Result<Ticket, NetworkError> {
        NodeRemote::send(self, request).await
    }

    async fn send_with_custom_ticket(
        &mut self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), NetworkError> {
        NodeRemote::send_with_custom_ticket(self, ticket, request).await
    }

    async fn send_callback_subscription(
        &mut self,
        request: NodeRequest,
    ) -> Result<KernelStreamSubscription, NetworkError> {
        NodeRemote::send_callback_subscription(self, request).await
    }

    async fn send_callback(&mut self, request: NodeRequest) -> Result<NodeResult, NetworkError> {
        NodeRemote::send_callback(self, request).await
    }

    fn account_manager(&self) -> &AccountManager {
        NodeRemote::account_manager(self)
    }

    fn get_next_ticket(&self) -> Ticket {
        NodeRemote::get_next_ticket(self)
    }
}

impl Debug for NodeRemote {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HdpServerRemote")
    }
}

impl NodeRemote {
    /// Creates a new [HdpServerRemote]
    pub(crate) fn new(
        outbound_send_request_tx: BoundedSender<(NodeRequest, Ticket)>,
        callback_handler: KernelAsyncCallbackHandler,
        account_manager: AccountManager,
        node_type: NodeType,
    ) -> Self {
        // starts at 1. Ticket 0 is for reserved
        Self {
            outbound_send_request_tx,
            inner: Arc::new(HdpServerRemoteInner {
                callback_handler,
                account_manager,
                node_type,
            }),
        }
    }

    /// Especially used to keep track of a conversation (b/c a certain ticket number may be expected)
    pub async fn send_with_custom_ticket(
        &mut self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), NetworkError> {
        self.outbound_send_request_tx.send((request, ticket)).await
    }

    /// Sends a request to the HDP server. This should always be used to communicate with the server
    /// in order to obtain a ticket
    pub async fn send(&mut self, request: NodeRequest) -> Result<Ticket, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_with_custom_ticket(ticket, request)
            .await
            .map(|_| ticket)
    }

    /// Returns an error if the ticket is already registered for a callback
    pub async fn send_callback_custom_ticket(
        &mut self,
        request: NodeRequest,
        ticket: Ticket,
    ) -> Result<NodeResult, NetworkError> {
        let rx = self.inner.callback_handler.register_future(ticket)?;
        match self.send_with_custom_ticket(ticket, request).await {
            Ok(_) => rx
                .await
                .map_err(|err| NetworkError::Generic(err.to_string())),

            Err(err) => {
                self.inner.callback_handler.remove_listener(ticket);
                Err(err)
            }
        }
    }

    /// Returns an error if the ticket is already registered for a stream-callback
    pub(crate) async fn send_callback_subscription_custom_ticket(
        &mut self,
        request: NodeRequest,
        ticket: Ticket,
    ) -> Result<KernelStreamSubscription, NetworkError> {
        let rx = self.inner.callback_handler.register_stream(ticket)?;
        match self.send_with_custom_ticket(ticket, request).await {
            Ok(_) => Ok(rx),

            Err(err) => {
                self.inner.callback_handler.remove_listener(ticket);
                Err(err)
            }
        }
    }

    /// Convenience method for sending and awaiting for a response for the related ticket
    pub async fn send_callback_subscription(
        &mut self,
        request: NodeRequest,
    ) -> Result<KernelStreamSubscription, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_callback_subscription_custom_ticket(request, ticket)
            .await
    }

    /// Convenience method for sending and awaiting for a response for the related ticket
    pub async fn send_callback(
        &mut self,
        request: NodeRequest,
    ) -> Result<NodeResult, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_callback_custom_ticket(request, ticket).await
    }

    /// Convenience method for sending and awaiting for a response for the related ticket (with a timeout)
    pub async fn send_callback_timeout(
        &mut self,
        request: NodeRequest,
        timeout: Duration,
    ) -> Result<NodeResult, NetworkError> {
        tokio::time::timeout(timeout, self.send_callback(request))
            .await
            .map_err(|_| NetworkError::Timeout(0))?
    }

    /// Safely shutsdown the internal server
    pub async fn shutdown(&mut self) -> Result<(), NetworkError> {
        let _ = self.send(NodeRequest::Shutdown).await?;
        self.outbound_send_request_tx.close().await
    }

    // Note: when two nodes create a ticket, there may be equivalent values
    // Thus, use UUID's instead
    pub fn get_next_ticket(&self) -> Ticket {
        uuid::Uuid::new_v4().as_u128().into()
    }

    #[allow(clippy::result_large_err)]
    pub fn try_send_with_custom_ticket(
        &mut self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), TrySendError<(NodeRequest, Ticket)>> {
        self.outbound_send_request_tx.try_send((request, ticket))
    }

    #[allow(clippy::result_large_err)]
    pub fn try_send(
        &mut self,
        request: NodeRequest,
    ) -> Result<(), TrySendError<(NodeRequest, Ticket)>> {
        let ticket = self.get_next_ticket();
        self.try_send_with_custom_ticket(ticket, request)
    }

    pub fn local_node_type(&self) -> &NodeType {
        &self.inner.node_type
    }

    pub fn account_manager(&self) -> &AccountManager {
        &self.inner.account_manager
    }
}

impl Unpin for NodeRemote {}

impl Sink<(Ticket, NodeRequest)> for NodeRemote {
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Self as Sink<NodeRequest>>::poll_ready(self, cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: (Ticket, NodeRequest),
    ) -> Result<(), Self::Error> {
        Pin::new(&mut self.outbound_send_request_tx).start_send((item.1, item.0))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Self as Sink<NodeRequest>>::poll_flush(self, cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Self as Sink<NodeRequest>>::poll_close(self, cx)
    }
}

impl Sink<NodeRequest> for NodeRemote {
    type Error = NetworkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.outbound_send_request_tx).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: NodeRequest) -> Result<(), Self::Error> {
        let ticket = self.get_next_ticket();
        Pin::new(&mut self.outbound_send_request_tx).start_send((item, ticket))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.outbound_send_request_tx)
            .poll_flush(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.outbound_send_request_tx)
            .poll_close(cx)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }
}

/// A type sent through the server when a request is made
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Ticket(pub u128);

impl From<u128> for Ticket {
    fn from(val: u128) -> Self {
        Ticket(val)
    }
}

impl From<usize> for Ticket {
    fn from(val: usize) -> Self {
        (val as u128).into()
    }
}

impl Display for Ticket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
