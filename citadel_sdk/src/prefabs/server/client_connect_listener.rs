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
//! let kernel = Box::new(ClientConnectListenerKernel::new(|conn, remote| async move {
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
//! - [`ConnectionSuccess`]: Connection event data
//! - [`NodeResult`]: Network event handling
//!

use crate::prefabs::ClientServerRemote;
use crate::prelude::*;
use citadel_proto::prelude::async_trait;
use futures::Future;
use std::marker::PhantomData;

/// A kernel that executes a user-provided function each time
/// a client makes a connection
pub struct ClientConnectListenerKernel<F, Fut> {
    on_channel_received: F,
    node_remote: Option<NodeRemote>,
    _pd: PhantomData<Fut>,
}

impl<F, Fut> ClientConnectListenerKernel<F, Fut>
where
    F: Fn(ConnectionSuccess, ClientServerRemote) -> Fut + Send + Sync,
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
impl<F, Fut> NetKernel for ClientConnectListenerKernel<F, Fut>
where
    F: Fn(ConnectionSuccess, ClientServerRemote) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), NetworkError>> + Send + Sync,
{
    fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
        self.node_remote = Some(server_remote);
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_node_event_received(&self, message: NodeResult) -> Result<(), NetworkError> {
        match message {
            NodeResult::ConnectSuccess(ConnectSuccess {
                ticket: _,
                implicated_cid: cid,
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
                    None, // TODO: Add real handles
                    None,
                );
                (self.on_channel_received)(
                    ConnectionSuccess {
                        channel,
                        udp_channel_rx,
                        services,
                        cid,
                        session_security_settings,
                    },
                    client_server_remote,
                )
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
