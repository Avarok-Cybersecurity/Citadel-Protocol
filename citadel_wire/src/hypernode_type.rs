use std::net::SocketAddr;

/// Used for determining the proper action when loading the server
#[derive(Default, Copy, Clone, Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub enum NodeType {
    /// A server with a static IP address will choose this option
    Server(SocketAddr),
    /// A client/server behind a residential NAT will choose this (will specially will start the UPnP handler, but the method for symmetrical NATs works too; UPnP is just faster)
    #[default]
    Peer,
}

impl NodeType {
    pub fn bind_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Server(addr) => Some(*addr),
            _ => None,
        }
    }

    pub fn is_server(&self) -> bool {
        matches!(self, Self::Server(..))
    }

    pub fn is_peer(&self) -> bool {
        matches!(self, Self::Peer)
    }
}
