//! Server-Side Peer Processing Module for Citadel Protocol
//!
//! This module handles server-side operations for peer connections in the Citadel
//! Protocol network. It manages post-connection and post-registration states for
//! peer sessions on the server side.
//!
//! # Features
//!
//! - Post-connection state management
//! - Post-registration processing
//! - Server-side peer validation
//! - Session state tracking
//!
//! # Important Notes
//!
//! - Server-side operations only
//! - Requires established connections
//! - Manages peer session states
//! - Handles registration completion
//!
//! # Related Components
//!
//! - `post_connect`: Post-connection processing
//! - `post_register`: Post-registration handling
//! - `CitadelSession`: Session management
//! - `StateContainer`: State tracking

pub mod post_connect;
pub mod post_register;
