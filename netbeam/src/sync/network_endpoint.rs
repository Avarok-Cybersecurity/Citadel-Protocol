use crate::reliable_conn::{ConnAddr, ReliableOrderedConnectionToTarget};
use crate::sync::network_application::NetworkApplication;
use crate::sync::subscription::Subscribable;
use crate::sync::RelativeNodeType;
use std::net::SocketAddr;
use std::ops::Deref;

/// A network application endowed with socket addrs
#[derive(Clone)]
pub struct NetworkEndpoint {
    endpoint: NetworkApplication,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl ConnAddr for NetworkEndpoint {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
}

impl Deref for NetworkEndpoint {
    type Target = NetworkApplication;

    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}

impl NetworkEndpoint {
    pub async fn register<T: ReliableOrderedConnectionToTarget + 'static>(
        relative_node_type: RelativeNodeType,
        conn: T,
    ) -> Result<Self, anyhow::Error> {
        let (local_addr, peer_addr) = (conn.local_addr()?, conn.peer_addr()?);
        let endpoint = NetworkApplication::register(relative_node_type, conn).await?;
        Ok(Self {
            endpoint,
            local_addr,
            peer_addr,
        })
    }

    pub fn is_initiator(&self) -> bool {
        self.node_type() == RelativeNodeType::Initiator
    }
}

#[cfg(test)]
mod tests {
    use crate::reliable_conn::ConnAddr;
    use crate::sync::test_utils::create_streams_with_addrs;
    use citadel_io::tokio;

    #[tokio::test]
    async fn main() {
        let (server, client) = create_streams_with_addrs().await;
        println!(
            "Hello, world {:?} {:?} {:?} {:?}",
            server.local_addr(),
            server.peer_addr(),
            client.local_addr(),
            client.peer_addr()
        );
    }
}
