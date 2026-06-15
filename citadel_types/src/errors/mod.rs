//! Error types for this crate.
//!
//! As part of the workspace-wide error consolidation, the former `Error` enum has been replaced by
//! the canonical [`citadel_io::NetworkError`]. `Error` is kept here as an alias so existing
//! `citadel_types::errors::Error` paths keep resolving; construct values via the typed helpers on
//! [`NetworkError`] (e.g. `Error::invalid_length()`, `Error::generic(msg)`).

pub use citadel_io::error::{ErrorCode, NetworkError};

/// Backwards-compatible alias for the canonical workspace error type.
pub type Error = NetworkError;
