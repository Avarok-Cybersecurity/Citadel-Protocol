use crate::udp_traversal::linear::{RelativeNodeType, LinearUdpHolePunchImpl};
use tokio::net::UdpSocket;
use std::net::SocketAddr;
use crate::udp_traversal::hole_punched_udp_socket_addr::HolePunchedSocketAddr;
use crate::error::FirewallError;
use std::sync::Arc;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use async_trait::async_trait;

pub struct Method3Encrypted {
    this_node_type: RelativeNodeType,
    encrypted_container: Arc<EncryptedConfigContainer>
}

impl Method3Encrypted {
    pub fn new(this_node_type: RelativeNodeType, encrypted_container: Arc<EncryptedConfigContainer>) -> Self {
        Self { this_node_type, encrypted_container }
    }
}


#[async_trait]
impl LinearUdpHolePunchImpl for Method3Encrypted {
    async fn execute(&self, _sockets: &mut Vec<UdpSocket>, _endpoints: &Vec<SocketAddr>) -> Result<Vec<HolePunchedSocketAddr>, FirewallError> {
        Ok(Vec::with_capacity(0))
    }
}