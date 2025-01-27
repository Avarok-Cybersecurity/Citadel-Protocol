//! Client Connection Event Handler
//!
//! This module provides a network kernel that executes custom logic whenever a client
//! establishes a connection. It's particularly useful for implementing server-side
//! connection handling, authentication, and session initialization.
//!
//! # Features
//! - Custom connection handling
//! - Asynchronous event processing
//! - Type-safe callback execution
//! - Session security management
//! - UDP channel support
//! - Service discovery integration
//!
//! # Example:
//! ```rust
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::prefabs::server::client_connect_listener::ClientConnectListenerKernel;
//!
//! # fn main() -> Result<(), NetworkError> {
//! let kernel = Box::new(ClientConnectListenerKernel::<_, _, StackedRatchet>::new(|conn| async move {
//!     println!("Client connected!");
//!     Ok(())
//! }));
//! # Ok(())
//! # }
//! ```
//!
//! # Important Notes
//! - Callbacks must be Send + Sync
//! - Futures must be Send + Sync
//! - Handles both TCP and UDP channels
//! - Automatic security settings handling
//!
//! # Related Components
//! - [`NetKernel`]: Base trait for network kernels
//! - [`ClientServerRemote`]: Client-server communication
//! - [`CitadelClientServerConnection`]: Connection event data
//! - [`NodeResult`]: Network event handling
//!
//! [`NetKernel`]: crate::prelude::NetKernel
//! [`ClientServerRemote`]: crate::prelude::ClientServerRemote
//! [`CitadelClientServerConnection`]: crate::prelude::CitadelClientServerConnection
//! [`NodeResult`]: crate::prelude::NodeResult

use crate::prefabs::ClientServerRemote;
use crate::prelude::*;
use citadel_proto::prelude::async_trait;
use futures::Future;
use std::marker::PhantomData;

/// A kernel that executes a user-provided function each time
/// a client makes a connection
pub struct ClientConnectListenerKernel<F, Fut, R: Ratchet> {
    on_channel_received: F,
    node_remote: Option<NodeRemote<R>>,
    _pd: PhantomData<Fut>,
}

impl<F, Fut, R: Ratchet> ClientConnectListenerKernel<F, Fut, R>
where
    F: Fn(CitadelClientServerConnection<R>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), NetworkError>> + Send + Sync,
{
    pub fn new(on_channel_received: F) -> Self {
        Self {
            on_channel_received,
            node_remote: None,
            _pd: Default::default(),
        }
    }
}

#[async_trait]
impl<F, Fut, R: Ratchet> NetKernel<R> for ClientConnectListenerKernel<F, Fut, R>
where
    F: Fn(CitadelClientServerConnection<R>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), NetworkError>> + Send + Sync,
{
    fn load_remote(&mut self, server_remote: NodeRemote<R>) -> Result<(), NetworkError> {
        self.node_remote = Some(server_remote);
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_node_event_received(&self, message: NodeResult<R>) -> Result<(), NetworkError> {
        match message {
            NodeResult::ConnectSuccess(ConnectSuccess {
                ticket: _,
                session_cid: cid,
                remote_addr: _,
                is_personal: _,
                v_conn_type: conn_type,
                services,
                welcome_message: _,
                channel,
                udp_rx_opt: udp_channel_rx,
                session_security_settings,
            }) => {
                let client_server_remote = ClientServerRemote::new(
                    conn_type,
                    self.node_remote.clone().unwrap(),
                    session_security_settings,
                    None,
                    None,
                );
                (self.on_channel_received)(CitadelClientServerConnection {
                    remote: client_server_remote.clone(),
                    channel: Some(channel),
                    udp_channel_rx,
                    services,
                    cid,
                    session_security_settings,
                })
                .await
            }

            other => {
                log::trace!(target: "citadel", "Unhandled server signal: {:?}", other);
                Ok(())
            }
        }
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}
