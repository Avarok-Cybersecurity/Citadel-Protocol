//! Kernel Trait Definitions for Citadel Protocol
//!
//! This module defines the core trait interfaces that all kernel implementations must satisfy.
//! It provides the contract between the high-level protocol operations and the underlying
//! network implementations.
//!
//! # Features
//!
//! - Abstract network kernel interface definition
//! - Protocol-agnostic message handling
//! - Asynchronous operation support
//! - Session management traits
//! - Error handling specifications
//!
//! # Important Notes
//!
//! - All kernel implementations must be thread-safe
//! - Methods are asynchronous and return Futures
//! - Implementations must handle connection state
//! - Error types must implement std::error::Error
//!
//! # Related Components
//!
//! - `kernel/mod.rs`: Main kernel module implementation
//! - `kernel_executor.rs`: Execution runtime
//! - `kernel_communicator.rs`: Communication handling
//! - `error.rs`: Protocol error definitions

use async_trait::async_trait;

use crate::error::NetworkError;
use crate::proto::node_result::NodeResult;
use crate::proto::remote::NodeRemote;
use auto_impl::auto_impl;

/// The [`NetKernel`] is the thread-safe interface between the single-threaded OR multi-threaded async
/// protocol and your network application
#[async_trait]
#[auto_impl(Box, &mut)]
pub trait NetKernel: Send + Sync {
    /// when the kernel executes, it will be given a handle to the server
    fn load_remote(&mut self, node_remote: NodeRemote) -> Result<(), NetworkError>;
    /// After the server remote is passed to the kernel, this function will be called once to allow the application to make any initial calls
    async fn on_start(&self) -> Result<(), NetworkError>;
    /// When the server processes a valid entry, the value is sent here. Each call to 'on_node_event_received' is done
    /// *concurrently* (but NOT in *parallel*). This allows code inside this function to await without blocking new incoming
    /// messages
    async fn on_node_event_received(&self, message: NodeResult) -> Result<(), NetworkError>;
    /// When the system is ready to shutdown, this is called
    async fn on_stop(&mut self) -> Result<(), NetworkError>;
}
