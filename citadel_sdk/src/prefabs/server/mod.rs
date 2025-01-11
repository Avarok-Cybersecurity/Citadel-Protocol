//! Server-Side Network Components
//!
//! This module provides pre-built server-side networking components for the Citadel Protocol.
//! It includes implementations for common server tasks such as file transfer handling,
//! client connection management, and internal service integration.
//!
//! # Features
//! - File transfer acceptance
//! - Client connection handling
//! - Internal service support
//! - Minimal processing kernels
//! - Event-driven architecture
//! - Automatic resource management
//! - Service integration patterns
//!
//! # Example
//! ```rust
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::prefabs::server::accept_file_transfer_kernel::AcceptFileTransferKernel;
//! use citadel_sdk::prefabs::server::client_connect_listener::ClientConnectListenerKernel;
//! use citadel_sdk::prefabs::server::empty::EmptyKernel;
//! use citadel_sdk::prefabs::server::internal_service::InternalServiceKernel;
//! use citadel_io::tokio;
//! use hyper::service::service_fn;
//! use hyper::{Body, Request, Response};
//! use std::convert::Infallible;
//!
//! # fn main() -> Result<(), NetworkError> {
//! // Create a basic server with file transfer support
//! let kernel = Box::new(AcceptFileTransferKernel::<StackedRatchet>::default());
//!
//! // Create a server that listens for client connections
//! let kernel = Box::new(ClientConnectListenerKernel::<_, _, StackedRatchet>::new(|conn| async move {
//!     println!("Client connected!");
//!     Ok(())
//! }));
//!
//! // Create a minimal server with no additional processing
//! let kernel = Box::new(EmptyKernel::<StackedRatchet>::default());
//!
//! // Create a server with internal service support (e.g., HTTP server)
//! let kernel = Box::new(InternalServiceKernel::<_, _, StackedRatchet>::new(|_comm| async move {
//!     let service = service_fn(|_req: Request<Body>| async move {
//!         Ok::<_, Infallible>(Response::new(Body::empty()))
//!     });
//!     Ok(())
//! }));
//! # Ok(())
//! # }
//! ```
//!
//! # Important Notes
//! - Kernels are composable components
//! - Each kernel serves a specific purpose
//! - Resource cleanup is automatic
//! - Event handling is asynchronous
//!
//! # Related Components
//! - [`accept_file_transfer_kernel`]: File transfer handling
//! - [`client_connect_listener`]: Client connection management
//! - [`internal_service`]: Internal service support
//! - [`empty`]: Minimal processing kernel
//!
/// A kernel that accepts all inbound file transfer requests for basic file transfers
/// AND RE-VFS transfers
pub mod accept_file_transfer_kernel;
/// A kernel that reacts to new channels created, allowing communication with new clients.
/// Useful for when a server needs to send messages to clients
pub mod client_connect_listener;
/// A non-reactive kernel that does no additional processing on top of the protocol
pub mod empty;
/// For internal services (e.g., a Hyper webserver)
pub mod internal_service;
