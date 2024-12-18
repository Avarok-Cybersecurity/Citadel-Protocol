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

    pub fn implicated_cid(&self) -> Option<u64> {
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
