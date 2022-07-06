use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// For saving the state of client-side connections
pub struct ConnectionInfo {
    /// The address of the adjacent node
    pub addr: SocketAddr,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
/// For saving the state of client-side connections
pub enum ConnectProtocol {
    /// Uses the transmission control protocol
    Tcp,
    /// The domain
    Tls(Option<String>),
    /// Quic
    Quic(Option<String>),
}

impl ConnectProtocol {
    /// Gets domain
    pub fn get_domain(&self) -> Option<String> {
        match self {
            Self::Tcp => None,
            Self::Tls(t) => t.clone(),
            Self::Quic(t) => t.clone(),
        }
    }
}

impl Display for ConnectionInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "addr: {}", self.addr)
    }
}
