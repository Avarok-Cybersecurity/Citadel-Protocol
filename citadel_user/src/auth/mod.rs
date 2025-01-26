//! Authentication Mode Management
//!
//! This module provides authentication mode handling for Citadel Network Accounts (CNACs),
//! supporting both password-based and passwordless authentication methods.
//!
//! # Features
//!
//! * **Authentication Modes**
//!   - Argon2id password-based authentication
//!   - Passwordless authentication
//!   - Username management
//!   - Full name handling
//!
//! * **Security Features**
//!   - Secure password hashing
//!   - Mode-specific data storage
//!   - Authentication state management
//!
//! # Important Notes
//!
//! * All authentication modes require unique usernames
//! * Argon2id is used for secure password hashing
//! * Passwordless mode still maintains user identity
//! * Authentication data is serializable for storage
//! * Mode can be determined at runtime
//!
//! # Related Components
//!
//! * `proposed_credentials` - Credential validation
//! * `ArgonContainerType` - Password hashing
//! * `ClientNetworkAccount` - Uses authentication modes
//! * `AccountManager` - Manages authentication

#![allow(missing_docs, dead_code)]
use citadel_crypt::argon::argon_container::ArgonContainerType;
use serde::{Deserialize, Serialize};

/// For handling misc requirements
pub mod proposed_credentials;

#[derive(Serialize, Deserialize)]
/// For storing data inside the CNACs. Both need unique usernames b/c of the unique username requirement on the SQL backend
pub enum DeclaredAuthenticationMode {
    Argon {
        username: String,
        full_name: String,
        argon: ArgonContainerType,
    },
    Transient {
        username: String,
        full_name: String,
    },
}

impl DeclaredAuthenticationMode {
    pub fn username(&self) -> &str {
        match self {
            Self::Argon { username, .. } => username.as_str(),
            Self::Transient { username, .. } => username.as_str(),
        }
    }

    pub fn full_name(&self) -> &str {
        match self {
            Self::Argon { full_name, .. } => full_name.as_str(),
            Self::Transient { full_name, .. } => full_name.as_str(),
        }
    }

    pub fn argon_container(&self) -> Option<&ArgonContainerType> {
        match self {
            Self::Argon { argon, .. } => Some(argon),
            Self::Transient { .. } => None,
        }
    }

    pub fn is_transient(&self) -> bool {
        match self {
            Self::Argon { .. } => false,
            Self::Transient { .. } => true,
        }
    }
}
