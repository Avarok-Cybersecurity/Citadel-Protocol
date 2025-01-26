//! Authentication Request Types for Citadel Protocol
//!
//! This module defines the authentication request types and structures used for establishing
//! connections in the Citadel Protocol. It supports both credential-based and passwordless
//! authentication methods.
//!
//! # Features
//! - **Credential Authentication**: Username/password-based authentication
//! - **Passwordless Authentication**: Device-based transient connections
//! - **Secure Credential Handling**: Uses SecBuffer for password protection
//! - **User Identification**: Supports both CID and username-based identification
//! - **Server Address Management**: Handles server connection information
//!
//! # Usage Example
//! ```rust
//! use citadel_proto::auth::AuthenticationRequest;
//! use citadel_types::user::UserIdentifier;
//! use citadel_types::crypto::SecBuffer;
//! use std::net::SocketAddr;
//! use uuid::Uuid;
//!
//! // Credential-based authentication
//! let cred_auth = AuthenticationRequest::credentialed(
//!     UserIdentifier::from("username"),
//!     SecBuffer::from("password")
//! );
//!
//! // Passwordless authentication
//! let server_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
//! let uuid = Uuid::new_v4();
//! let transient_auth = AuthenticationRequest::transient(uuid, server_addr);
//! ```
//!
//! # Important Notes
//! - Passwords are always handled using SecBuffer for secure memory management
//! - Transient connections use device-specific cryptographic bundles
//! - CID extraction is only available for credential-based authentication
//! - Server addresses are required for passwordless authentication
//!
//! # Related Components
//! - `citadel_types::crypto::SecBuffer`: Secure credential storage
//! - `citadel_types::user::UserIdentifier`: User identification types
//! - `proto::packet_processor::connect_packet`: Connection handling
//! - `proto::validation`: Authentication validation
//!

use citadel_types::crypto::SecBuffer;
use citadel_types::user::UserIdentifier;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

/// Arguments for connecting to a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationRequest {
    /// Credentials used for the connection
    Credentialed {
        id: UserIdentifier,
        password: SecBuffer,
    },
    /// No credentials/one-time connection
    Passwordless {
        username: String,
        server_addr: SocketAddr,
    },
}

impl AuthenticationRequest {
    /// Credentials used for connecting (registration implied to have occurred)
    pub fn credentialed<T: Into<UserIdentifier>, V: Into<SecBuffer>>(id: T, password: V) -> Self {
        Self::Credentialed {
            id: id.into(),
            password: password.into(),
        }
    }

    /// No credentials will be used for login, only a one-time device-dependent cryptographic bundle
    pub fn transient(uuid: Uuid, server_addr: SocketAddr) -> Self {
        Self::Passwordless {
            username: uuid.to_string(),
            server_addr,
        }
    }

    pub fn session_cid(&self) -> Option<u64> {
        match self {
            AuthenticationRequest::Credentialed { id, .. } => {
                if let UserIdentifier::ID(cid) = id {
                    Some(*cid)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
