//! Secure Buffer Management
//!
//! This module provides secure buffer implementations for efficient and safe
//! handling of sensitive data. It includes specialized buffers for both general
//! data and packet-specific operations.
//!
//! # Features
//!
//! - Memory-safe buffer implementations
//! - Zero-copy data handling where possible
//! - Automatic memory zeroing on drop
//! - Efficient packet writing utilities
//! - Partitioned buffer support
//!
//! # Components
//!
//! - [`partitioned_sec_buffer`]: Efficient partitioned buffer implementation
//! - [`sec_packet`]: Secure packet buffer implementation
//!
//! # Important Notes
//!
//! - All buffers implement automatic zeroing
//! - Memory is allocated only when needed
//! - Thread-safe implementations available
//! - Optimized for both small and large data sets
//!
//! # Related Components
//!
//! - [`crate::streaming_crypt_scrambler`] - Uses secure buffers for streaming
//! - [`crate::packet_vector`] - Packet handling utilities
//!

/// For efficient writing to data
pub mod partitioned_sec_buffer;
/// For efficient writing of data onto packets
pub mod sec_packet;
