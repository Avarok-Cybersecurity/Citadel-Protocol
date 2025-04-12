//! Server Miscellaneous Settings Management
//!
//! This module provides configuration settings for server nodes in the Citadel network,
//! focusing on authentication and credential management.
//!
//! # Features
//!
//! * Passwordless authentication control
//! * Credential requirement specifications
//! * Default settings configuration
//!
//! # Example
//!
//! ```rust
//! use citadel_user::server_misc_settings::ServerMiscSettings;
//! use citadel_user::credentials::CredentialRequirements;
//!
//! // Create custom server settings
//! let settings = ServerMiscSettings {
//!     allow_transient_connections: false,
//!     credential_requirements: CredentialRequirements::default(),
//! };
//!
//! // Or use default settings
//! let default_settings = ServerMiscSettings::default();
//! assert!(default_settings.allow_transient_connections); // Passwordless auth is enabled by default
//! ```
//!
//! # Important Notes
//!
//! * Enabling passwordless authentication (`allow_transient_connections`) should be done with caution
//!   and only in trusted environments
//! * Credential requirements are enforced even when creating new accounts
//! * Default settings prioritize ease of use over security - modify as needed for production
//!
//! # Related Components
//!
//! * [`CredentialRequirements`] - Defines password and username requirements
//! * `AccountManager` - Uses these settings for account creation and authentication
//! * `HyperNodeAccount` - Server-side account management

use crate::credentials::CredentialRequirements;

/// Miscellaneous settings for a node serving connections
#[derive(Clone)]
pub struct ServerMiscSettings {
    /// If enabled, allows inbound connections to use no credentials when logging-in
    pub allow_transient_connections: bool,
    /// Enforces specific requirements on credentials
    pub credential_requirements: CredentialRequirements,
}

impl Default for ServerMiscSettings {
    fn default() -> Self {
        Self {
            allow_transient_connections: true,
            credential_requirements: Default::default(),
        }
    }
}
