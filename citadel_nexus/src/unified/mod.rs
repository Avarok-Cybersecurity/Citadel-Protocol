//! Unified types that work across all platforms
//!
//! This module provides concrete implementations of the core traits that can
//! work across different platforms, wrapping platform-specific implementations
//! in a common interface.

pub mod stream;
pub mod listener;

pub use stream::*;
pub use listener::*;