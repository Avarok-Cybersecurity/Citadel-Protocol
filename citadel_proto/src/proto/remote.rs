//! # Citadel Protocol Remote Communication
//!
//! This module implements remote communication functionality for the Citadel Protocol.
//! It provides a high-level interface for nodes to communicate with each other and
//! with the server in a secure and efficient manner.
//!
//! ## Features
//!
//! - **Asynchronous Communication**: Non-blocking request/response patterns
//! - **Ticket Management**: Unique identifiers for tracking requests and responses
//! - **Callback Support**: Subscription-based callbacks for event handling
//! - **Error Handling**: Comprehensive error handling for network operations
//! - **Account Management**: Integration with account management system
//!
//! ## Components
//!
//! - **NodeRemote**: Main interface for node communication
//! - **Remote Trait**: Core functionality definition
//! - **Ticket System**: Request tracking and correlation
//!
//! ## Security
//!
//! All communication is secured using:
//! - Post-quantum cryptography
//! - Secure ticket generation
//! - Protected channel establishment
//!
//! ## Usage Example
//!
//! ```no_run
//! use citadel_proto::remote::NodeRemote;
//! use citadel_proto::prelude::NodeRequest;
//!
//! // Create a request
//! let request = NodeRequest::new();
//!
//! // Send request and get ticket
//! let ticket = remote.send(request)?;
//!
//! // Or use callback subscription
//! let subscription = remote.send_callback_subscription(request)?;
//! ```

use crate::error::NetworkError;
use crate::kernel::kernel_communicator::{
    CallbackKey, KernelAsyncCallbackHandler, KernelStreamSubscription,
};
use crate::prelude::NodeRequest;
use crate::proto::node::CitadelNodeRemoteInner;
use crate::proto::outbound_sender::BoundedSender;
use bytemuck::NoUninit;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::mpsc::error::TrySendError;
use citadel_user::account_manager::AccountManager;
use citadel_wire::hypernode_type::NodeType;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;

/// allows convenient communication with the server
#[derive(Clone)]
pub struct NodeRemote<R: Ratchet> {
    outbound_send_request_tx: BoundedSender<(NodeRequest, Ticket)>,
    inner: Arc<CitadelNodeRemoteInner<R>>,
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Box, &mut, &, Arc)]
pub trait Remote<R: Ratchet>: Clone + Send {
    /// Sends a request to the server and returns a ticket for tracking the response.
    async fn send(&self, request: NodeRequest) -> Result<Ticket, NetworkError> {
        let ticket = self.get_next_ticket();
        self.send_with_custom_ticket(ticket, request)
            .await
            .map(|_| ticket)
    }

    /// Sends a request to the server with a custom ticket.
    async fn send_with_custom_ticket(
        &self,
        ticket: Ticket,
        request: NodeRequest,
    ) -> Result<(), NetworkError>;

    /// Sends a request to the server and returns a subscription for callback events.
    async fn send_callback_subscription(
        &self,
        request: NodeRequest,
    ) -> Result<KernelStreamSubscription, NetworkError>;

    /// Returns the account manager instance.
    fn account_manager(&self) -> &AccountManager<R, R>;

    /// Returns the next available ticket.
    fn get_next_ticket(&self) -> Ticket;
}

#[async_trait::async_trait]
impl<R: Ratchet> Remote<R> for NodeRemote<R> {
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

    fn account_manager(&self) -> &AccountManager<R, R> {
        NodeRemote::account_manager(self)
    }

    fn get_next_ticket(&self) -> Ticket {
        NodeRemote::get_next_ticket(self)
    }
}

impl<R: Ratchet> Debug for NodeRemote<R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CitadelNodeRemote")
    }
}

impl<R: Ratchet> NodeRemote<R> {
    /// Creates a new [`NodeRemote`] instance.
    pub(crate) fn new(
        outbound_send_request_tx: BoundedSender<(NodeRequest, Ticket)>,
        callback_handler: KernelAsyncCallbackHandler,
        account_manager: AccountManager<R, R>,
        node_type: NodeType,
    ) -> Self {
        // starts at 1. Ticket 0 is for reserved
        Self {
            outbound_send_request_tx,
            inner: Arc::new(CitadelNodeRemoteInner {
                callback_handler,
                account_manager,
                node_type,
            }),
        }
    }

    /// Sends a request to the server with a custom ticket.
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

    /// Sends a request to the server and returns a ticket for tracking the response.
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
            session_cid: request.session_cid(),
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

    pub fn account_manager(&self) -> &AccountManager<R, R> {
        &self.inner.account_manager
    }
}

impl<R: Ratchet> Unpin for NodeRemote<R> {}

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
