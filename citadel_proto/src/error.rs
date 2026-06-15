//! This crate's error type is the canonical workspace-wide [`citadel_io::NetworkError`].
//! Kept here as a re-export so existing `crate::error::NetworkError` paths resolve unchanged.
pub use citadel_io::error::NetworkError;
