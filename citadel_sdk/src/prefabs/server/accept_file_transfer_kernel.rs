//! Automatic File Transfer Acceptance
//!
//! This module provides a simple network kernel that automatically accepts and processes
//! all incoming file transfers. It's useful for server-side implementations that need
//! to handle file uploads without custom processing.
//!
//! # Features
//! - Automatic file transfer acceptance
//! - Silent processing of transfers
//! - Zero configuration required
//! - Minimal resource usage
//! - Error handling for transfers
//!
//! # Example:
//! ```rust
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::prefabs::server::accept_file_transfer_kernel::AcceptFileTransferKernel;
//!
//! # fn main() -> Result<(), NetworkError> {
//! let kernel = Box::new(AcceptFileTransferKernel::default());
//! # Ok(())
//! # }
//! ```
//!
//! # Important Notes
//! - All file transfers are automatically accepted
//! - No customization of transfer handling
//! - Transfers are processed silently
//! - Errors are logged but not propagated
//!
//! # Related Components
//! - [`NetKernel`]: Base trait for network kernels
//! - [`ObjectTransferHandler`]: File transfer processing
//! - [`NodeResult`]: Network event handling
//!

use crate::prelude::*;

#[derive(Default)]
pub struct AcceptFileTransferKernel;

#[async_trait]
impl NetKernel for AcceptFileTransferKernel {
    fn load_remote(&mut self, _node_remote: NodeRemote) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_node_event_received(&self, message: NodeResult) -> Result<(), NetworkError> {
        if let NodeResult::ObjectTransferHandle(mut handle) = message {
            let _ = handle
                .handle
                .exhaust_stream()
                .await
                .map_err(|err| NetworkError::Generic(err.into_string()))?;
        }

        Ok(())
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}
