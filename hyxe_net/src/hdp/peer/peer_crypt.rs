use serde::{Serialize, Deserialize};
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
use crate::hdp::peer::peer_layer::UdpMode;
use std::net::SocketAddr;
use hyxe_wire::nat_identification::NatType;
use crate::hdp::hdp_node::TlsDomain;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum KeyExchangeProcess {
    // alice sends public key
    Stage0(Vec<u8>, SessionSecuritySettings, UdpMode),
    // Bob sends ciphertext, addr
    Stage1(Vec<u8>, Option<PeerNatInfo>),
    // Alice sends a sync time over. Server takes care of external addr
    Stage2(i64, Option<PeerNatInfo>),
    // Sends a signal to the other side validating that it established a connection
    // However, the other side must thereafter receiving prove that it's who they claim it is
    // to prevent MITM attacks
    HolePunchEstablished,
    // once the adjacent side confirms that they are who they claim they are, then the local node
    // can update its endpoint container to allow exhange of information
    // the bool determines whether or not the connection was upgraded
    HolePunchEstablishedVerified(bool),
    // The hole-punch failed
    HolePunchFailed
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerNatInfo {
    // This is the location of the listener for the other peer as obtained by the central server
    pub peer_remote_addr_visible_from_server: SocketAddr,
    pub peer_internal_listener_addr: SocketAddr,
    pub peer_nat: NatType,
    pub tls_domain: TlsDomain
}

impl PeerNatInfo {
    /// Since symmetric NATs will change IP addressed between differing endpoints, we can't connect thereto. We can however connect when the IP is the same. We will assume the ip is the same as the one visible from the central server,
    /// additionally allowing for connections where the server + clients are on the LAN
    pub fn generate_proper_listener_connect_addr(&self, local_nat_type: &NatType) -> (bool, SocketAddr) {
        //let predicted_addr = self.peer_nat.predict_external_addr_from_local_bind_port(self.peer_unnated_listener_port).map(|r| SocketAddr::new(self.peer_remote_ip, r.port())).unwrap_or_else(|| SocketAddr::new(self.peer_remote_ip, self.peer_unnated_listener_port));
        let predicted_addr = self.peer_remote_addr_visible_from_server;
        let needs_turn = !self.peer_nat.stun_compatible(local_nat_type);
        (needs_turn, predicted_addr)
    }
}