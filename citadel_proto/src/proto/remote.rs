use crate::error::NetworkError;
use crate::kernel::kernel_communicator::{
    CallbackKey, KernelAsyncCallbackHandler, KernelStreamSubscription,
};
use crate::prelude::NodeRequest;
use crate::proto::node::HdpServerRemoteInner;
use crate::proto::outbound_sender::BoundedSender;
use bytemuck::NoUninit;
use citadel_io::tokio::sync::mpsc::error::TrySendError;
use citadel_user::account_manager::AccountManager;
use citadel_wire::hypernode_type::NodeType;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;

/// allows convenient communication with the server
#[derive(Clone)]
pub struct NodeRemote {
    outbound_send_request_tx: BoundedSender<(NodeRequest, Ticket)>,
    inner: Arc<HdpServerRemoteInner>,
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Box, &mut, &, Arc)]
pub trait Remote: Clone + Send {
    async fn send(&self, request: NodeRequest) -> Result<Ticket, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_with_custom_ticket(ticket, request)
            .await
            .map(|_| ticket)
    }

    async fn send_with_custom_ticket(
        &self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), NetworkError>;
    async fn send_callback_subscription(
        &self,
        request: NodeRequest,
    ) -> Result<KernelStreamSubscription, NetworkError>;
    fn account_manager(&self) -> &AccountManager;
    fn get_next_ticket(&self) -> Ticket;
}

#[async_trait::async_trait]
impl Remote for NodeRemote {
    async fn send(&self, request: NodeRequest) -> Result<Ticket, NetworkError> {
        NodeRemote::send(self, request).await
    }

    async fn send_with_custom_ticket(
        &self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), NetworkError> {
        NodeRemote::send_with_custom_ticket(self, ticket, request).await
    }

    async fn send_callback_subscription(
        &self,
        request: NodeRequest,
    ) -> Result<KernelStreamSubscription, NetworkError> {
        NodeRemote::send_callback_subscription(self, request).await
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
    /// Creates a new [`NodeRemote`]
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
        &self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), NetworkError> {
        self.outbound_send_request_tx
            .send((request, ticket))
            .await
            .map_err(|err| {
                let reason = err.to_string();
                NetworkError::NodeRemoteSendError {
                    reason,
                    request: Box::new(err.0 .0),
                }
            })
    }

    /// Sends a request to the HDP server. This should always be used to communicate with the server
    /// in order to obtain a ticket
    pub async fn send(&self, request: NodeRequest) -> Result<Ticket, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_with_custom_ticket(ticket, request)
            .await
            .map(|_| ticket)
    }

    /// Returns an error if the ticket is already registered for a stream-callback
    pub(crate) async fn send_callback_subscription_custom_ticket(
        &self,
        request: NodeRequest,
        ticket: Ticket,
    ) -> Result<KernelStreamSubscription, NetworkError> {
        let callback_key = CallbackKey {
            ticket,
            implicated_cid: request.implicated_cid(),
        };

        let rx = self.inner.callback_handler.register_stream(callback_key)?;
        match self.send_with_custom_ticket(ticket, request).await {
            Ok(_) => Ok(rx),

            Err(err) => {
                log::error!(target: "citadel", "****** Error sending callback subscription: {err:?}");
                self.inner.callback_handler.remove_listener(callback_key);
                Err(err)
            }
        }
    }

    /// Convenience method for sending and awaiting for a response for the related ticket
    pub async fn send_callback_subscription(
        &self,
        request: NodeRequest,
    ) -> Result<KernelStreamSubscription, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_callback_subscription_custom_ticket(request, ticket)
            .await
    }

    /// Safely shutsdown the internal server
    pub async fn shutdown(&self) -> Result<(), NetworkError> {
        let _ = self.send(NodeRequest::Shutdown).await?;
        Ok(())
    }

    // Note: when two nodes create a ticket, there may be equivalent values
    // Thus, use UUID's instead
    pub fn get_next_ticket(&self) -> Ticket {
        uuid::Uuid::new_v4().as_u128().into()
    }

    #[allow(clippy::result_large_err)]
    pub fn try_send_with_custom_ticket(
        &self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), TrySendError<(NodeRequest, Ticket)>> {
        self.outbound_send_request_tx.try_send((request, ticket))
    }

    #[allow(clippy::result_large_err)]
    pub fn try_send(
        &self,
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

/// A type sent through the server when a request is made
#[derive(
    Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, NoUninit,
)]
#[repr(C)]
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
