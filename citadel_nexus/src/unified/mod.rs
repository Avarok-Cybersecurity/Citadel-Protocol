//! Unified types that work across all platforms
//!
//! This module provides concrete implementations of the core traits that can
//! work across different platforms, wrapping platform-specific implementations
//! in a common interface.

pub mod listener;
pub mod stream;

pub use listener::*;
pub use stream::*;
