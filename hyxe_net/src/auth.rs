use crate::prelude::{SecBuffer, UserIdentifier};
use std::net::SocketAddr;

/// Arguments for connecting to a node
#[derive(Debug, Clone)]
pub enum AuthenticationRequest {
    /// Credentials used for the connection
    Credentialed { id: UserIdentifier, password: SecBuffer },
    /// No credentials/one-time connection
    Passwordless { server_addr: SocketAddr }
}

impl AuthenticationRequest {
    /// Credentials used for connecting (registration implied to have occurred)
    pub fn credentialed<T: Into<UserIdentifier>, V: Into<SecBuffer>>(id: T, password: V) -> Self {
        Self::Credentialed { id: id.into(), password: password.into() }
    }

    /// No credentials will be used for login, only a one-time device-dependent cryptographic bundle
    pub const fn passwordless(server_addr: SocketAddr) -> Self {
        Self::Passwordless { server_addr }
    }
}