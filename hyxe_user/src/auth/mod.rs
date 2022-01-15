#![allow(missing_docs, dead_code)]
use hyxe_crypt::argon::argon_container::ArgonContainerType;
use serde::{Serialize, Deserialize};

/// For handling misc requirements
pub mod proposed_credentials;

#[derive(Serialize, Deserialize)]
/// For storing data inside the CNACs. Both need unique usernames b/c of the unique username requirement on the SQL backend
pub enum DeclaredAuthenticationMode {
    Argon { username: String, full_name: String, argon: ArgonContainerType },
    Passwordless { username: String, full_name: String }
}

impl DeclaredAuthenticationMode {
    pub fn username(&self) -> &str {
        match self {
            Self::Argon { username, .. } => username.as_str(),
            Self::Passwordless { username, .. } => username.as_str()
        }
    }

    pub fn full_name(&self) -> &str {
        match self {
            Self::Argon { full_name, .. } => full_name.as_str(),
            Self::Passwordless { full_name, .. } => full_name.as_str()
        }
    }

    pub fn argon_container(&self) -> Option<&ArgonContainerType> {
        match self {
            Self::Argon { argon, .. } => Some(argon),
            Self::Passwordless { .. } => None
        }
    }

    pub fn is_passwordless(&self) -> bool {
        match self {
            Self::Argon { .. } => false,
            Self::Passwordless { .. } => true
        }
    }
}