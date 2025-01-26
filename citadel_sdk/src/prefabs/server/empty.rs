//! Minimal Network Kernel
//!
//! This module provides a minimal network kernel implementation that performs no
//! additional processing on network events. It's useful for servers that need to
//! accept connections but don't require custom event handling.
//!
//! # Features
//! - Zero overhead processing
//! - Automatic event acceptance
//! - Minimal resource usage
//! - No state management
//! - Simple implementation
//!
//! # Example:
//! ```rust
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::prefabs::server::empty::EmptyKernel;
//!
//! # fn main() -> Result<(), NetworkError> {
//! let kernel = Box::new(EmptyKernel::<StackedRatchet>::default());
//! # Ok(())
//! # }
//! ```
//!
//! # Important Notes
//! - No event processing
//! - No connection handling
//! - No channel interaction
//! - Suitable for basic servers
//! - Not suitable for interactive servers
//!
//! # Related Components
//! - [`NetKernel`]: Base trait for network kernels
//! - [`NodeRemote`]: Server remote interface
//! - [`NodeResult`]: Network event handling
//!
//! [`NetKernel`]: crate::prelude::NetKernel
//! [`NodeRemote`]: crate::prelude::NodeRemote
//! [`NodeResult`]: crate::prelude::NodeResult

use citadel_proto::prelude::*;
use std::marker::PhantomData;

/// A kernel that does nothing to events in the protocol, nor does it cause any requests. A server that allows any and all connections with no special handlers would benefit from the use of this kernel.
/// This should never be used for interacting with peers/clients from the server, since to do so would deny the possibility of interacting with channels.
pub struct EmptyKernel<R: Ratchet>(PhantomData<R>);

impl<R: Ratchet> Default for EmptyKernel<R> {
    fn default() -> Self {
        Self(Default::default())
    }
}

#[async_trait]
impl<R: Ratchet> NetKernel<R> for EmptyKernel<R> {
    fn load_remote(&mut self, _server_remote: NodeRemote<R>) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_node_event_received(&self, _message: NodeResult<R>) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}
