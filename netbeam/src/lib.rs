//! # Netbeam
//!
//! A high-performance networking library providing multiplexing, reliable connections,
//! and synchronization primitives for building robust networked applications.
//!
//! ## Features
//!
//! - **Multiplexing**: Create multiple logical streams over a single connection
//! - **Reliable Connections**: Guaranteed ordered delivery of messages
//! - **Synchronization**: Thread-safe primitives for network applications
//! - **Time Tracking**: Precise timing utilities for network operations
//! - **Zero Unsafe Code**: Completely safe Rust implementation
//!
//! ## Core Components
//!
//! - `multiplex`: Multiplexed connection handling and stream management
//! - `reliable_conn`: Traits and implementations for reliable ordered connections
//! - `sync`: Synchronization primitives and network application utilities
//! - `time_tracker`: Precise timing utilities for network operations
//!
//! ## Example
//!
//! ```rust,no_run
//! use anyhow::Result;
//! use netbeam::multiplex::MultiplexedConn;
//! use netbeam::sync::SymmetricConvID;
//! use netbeam::reliable_conn::ReliableOrderedStreamToTarget;
//! use netbeam::sync::subscription::Subscribable;
//! use netbeam::sync::RelativeNodeType;
//!
//! async fn example() -> Result<()> {
//!     // This is just a placeholder - replace with your actual connection
//!     let conn = get_connection().await?;
//!     
//!     // Create a multiplexed connection
//!     let muxed_conn = MultiplexedConn::<SymmetricConvID>::new(RelativeNodeType::Initiator, conn);
//!     
//!     // Create a new stream with a unique ID
//!     let stream_id = 1.into();
//!     let mut stream = muxed_conn.subscribe(stream_id);
//!     
//!     // Send data
//!     stream.send_to_peer(b"Hello").await?;
//!     
//!     // Receive response
//!     let response = stream.recv().await?;
//!     println!("Received: {:?}", response);
//!     
//!     Ok(())
//! }
//! # async fn get_connection() -> Result<impl ReliableOrderedStreamToTarget> { Ok(citadel_io::tokio::net::TcpStream::connect("127.0.0.1:8080").await?) }
//! ```
//!
//! ## Synchronization Example
//!
//! ```rust,no_run
//! use anyhow::Result;
//! use netbeam::sync::primitives::net_mutex::NetMutex;
//! use netbeam::sync::subscription::Subscribable;
//!
//! async fn sync_example<S: Subscribable + 'static>(connection: &S) -> Result<()> {
//!     // Create a network-aware mutex
//!     let mutex = NetMutex::create(connection, Some(0)).await?;
//!     
//!     // Acquire the lock
//!     let mut guard = mutex.lock().await?;
//!     
//!     // Modify the protected data
//!     *guard += 1;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Design Philosophy
//!
//! Netbeam is built with the following principles:
//!
//! 1. **Safety**: Zero unsafe code, leveraging Rust's type system
//! 2. **Performance**: Efficient multiplexing and minimal overhead
//! 3. **Reliability**: Guaranteed message ordering and delivery
//! 4. **Flexibility**: Extensible traits for custom implementations
//!
//! ## Usage Notes
//!
//! - All network operations are async and require a Tokio runtime
//! - Proper error handling is essential as network operations can fail
//! - Stream IDs should be coordinated between endpoints
//! - Consider using the synchronization primitives for shared state
#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;

pub mod multiplex;
pub mod reliable_conn;
pub mod sync;
pub mod time_tracker;

/// A scoped future result type used internally by the crate.
///
/// This type alias represents a pinned, boxed future that returns a Result
/// and can be sent across thread boundaries.
pub(crate) type ScopedFutureResult<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, anyhow::Error>> + Send + 'a>>;
