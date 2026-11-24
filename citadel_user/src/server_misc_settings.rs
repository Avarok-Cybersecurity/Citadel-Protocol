//! Server Miscellaneous Settings Management
//!
//! This module provides configuration settings for server nodes in the Citadel network,
//! focusing on authentication and credential management.
//!
//! # Features
//!
//! * Whether transient accounts are allowed
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
//!     pq_sign_in: None,
//!     admission: None,
//! };
//!
//! // Or use default settings
//! let default_settings = ServerMiscSettings::default();
//! assert!(default_settings.allow_transient_connections); // transient accounts are allowed by default
//! ```
//!
//! # Important Notes
//!
//! * A transient account is a session with its own CID that the server never persists and that
//!   has no password. `allow_transient_connections` decides whether this server gives them out;
//!   a server built with `citadel_sdk`'s `NodeBuilder` says it with `with_transient_accounts`
//! * Credential requirements are enforced even when creating new accounts
//! * Default settings prioritize ease of use over security - modify as needed for production
//!
//! # Related Components
//!
//! * [`CredentialRequirements`] - Defines password and username requirements
//! * `AccountManager` - Uses these settings for account creation and authentication
//! * `HyperNodeAccount` - Server-side account management

use crate::auth::pq::admission::AdmissionPolicy;
use crate::auth::pq::server::PqAuthServerSettings;
use crate::credentials::CredentialRequirements;
use std::sync::Arc;

/// Miscellaneous settings for a node serving connections
#[derive(Clone)]
pub struct ServerMiscSettings {
    /// Whether a client may open a transient account here: a session with its own CID that this
    /// server never persists and that has no password. When `false`, such a request is refused
    /// with `ErrorCode::PasswordlessUnsupported` and every session belongs to a stored account.
    /// Allowed by default (see [`Default`]).
    pub allow_transient_connections: bool,
    /// Enforces specific requirements on credentials
    pub credential_requirements: CredentialRequirements,
    /// Post-quantum sign-in: the tenant's OPRF seed and the Argon2id parameters for new password
    /// factors. `None` keeps this server on the legacy Argon2 path only: it refuses post-quantum
    /// registrations (clients fall back) and upgrades no legacy account.
    pub pq_sign_in: Option<PqAuthServerSettings>,
    /// An optional check a FRESH sign-in or registration must pass before the server does any
    /// work on it, such as a Turnstile token (see [`crate::auth::pq::admission`]). `None`
    /// admits everyone. A resume-token reconnect is not asked; a recovery is (as `Recover`).
    pub admission: Option<Arc<dyn AdmissionPolicy>>,
}

impl Default for ServerMiscSettings {
    /// Transient accounts are allowed. That default is a deliberate product decision approved by
    /// the project owner (2026-11-24), not an implicit fallback: a transient account still has an
    /// identity (its CID) for as long as it is connected, and allowing it keeps existing servers
    /// and clients working as before. A server turns it off with `allow_transient_connections:
    /// false` (or `NodeBuilder::with_transient_accounts(false)`).
    fn default() -> Self {
        Self {
            allow_transient_connections: true,
            credential_requirements: Default::default(),
            pq_sign_in: None,
            admission: None,
        }
    }
}
