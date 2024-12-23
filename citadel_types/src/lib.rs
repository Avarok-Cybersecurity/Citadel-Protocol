//! # Citadel Types
//!
//! Core type definitions and utilities for the Citadel Protocol.
//! This crate provides fundamental types, error definitions, and utilities
//! used throughout the Citadel Protocol ecosystem.
//!
//! ## Core Modules
//!
//! - **crypto**: Cryptographic types and utilities
//!   - Secure memory buffers
//!   - Cryptographic parameters
//!   - Algorithm definitions
//!   - Security level specifications
//!
//! - **errors**: Error types and handling
//!   - Protocol-specific errors
//!   - Error conversion traits
//!   - Result type aliases
//!
//! - **proto**: Protocol-specific types
//!   - Message definitions
//!   - Protocol constants
//!   - Serialization formats
//!
//! - **user**: User-related types
//!   - User identifiers
//!   - Authentication data
//!   - Session information
//!
//! - **utils**: General utilities
//!   - Validation functions
//!   - Helper traits
//!   - Common constants
//!
//! ## Usage
//!
//! The crate provides a prelude module for convenient imports:
//!
//! ```rust
//! use citadel_types::prelude::*;
//!
//! // Use crypto types
//! let secure_buffer = SecBuffer::empty();
//! let params = CryptoParameters::default();
//! ```
//!
//! ## Features
//!
//! - Memory-secure types for sensitive data
//! - Comprehensive error handling
//! - Serialization support via serde
//! - Validation utilities
//! - Type-safe protocol definitions

#![allow(non_camel_case_types)]

/// Common imports for working with Citadel types.
///
/// This module re-exports the most commonly used types from the crate's
/// modules, providing a convenient way to import multiple items at once.
pub mod prelude {
    pub use crate::crypto::*;
    pub use crate::proto::*;
    pub use crate::user::*;
}

/// Cryptographic types and utilities.
pub mod crypto;

/// Error types and handling.
pub mod errors;

/// Protocol-specific message and data types.
pub mod proto;

/// User-related types and data structures.
pub mod user;

/// General utility functions and helpers.
pub mod utils;
