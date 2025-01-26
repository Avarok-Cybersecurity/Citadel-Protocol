//! Shared Network Components
//!
//! This module contains network components that are shared between client and server
//! implementations in the Citadel Protocol. These components provide common
//! functionality used across different network roles.
//!
//! # Features
//! - Internal service integration
//! - Shared utility functions
//! - Common type definitions
//! - Cross-role functionality
//!
//! # Important Notes
//! - Components are role-agnostic
//! - Thread-safe implementations
//! - Async-first design
//!
//! # Related Components
//! - [`internal_service`]: Service integration
//! - [`client`]: Client-side components
//! - [`server`]: Server-side components
//!
//! [`internal_service`]: crate::prefabs::server::internal_service
//! [`client`]: crate::prefabs::client
//! [`server`]: crate::prefabs::server
pub mod internal_service;
