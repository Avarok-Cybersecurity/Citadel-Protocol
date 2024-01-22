use crate::proto::node::TlsDomain;
use citadel_types::proto::SessionSecuritySettings;
use citadel_types::proto::UdpMode;
use citadel_wire::nat_identification::NatType;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum KeyExchangeProcess {
    // alice sends public key
    Stage0(Vec<u8>, SessionSecuritySettings, UdpMode),
    // Bob sends ciphertext, addr
    Stage1(Vec<u8>, Option<PeerNatInfo>),
    // Alice sends a sync time over. Server takes care of external addr
    Stage2(i64, Option<PeerNatInfo>),
    // The hole-punch failed
    HolePunchFailed,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerNatInfo {
    // This is the location of the listener for the other peer as obtained by the central server
    pub peer_remote_addr_visible_from_server: SocketAddr,
    pub peer_nat: NatType,
    pub tls_domain: TlsDomain,
}

impl PeerNatInfo {
    pub fn generate_proper_listener_connect_addr(
        &self,
        local_nat_type: &NatType,
    ) -> (bool, SocketAddr) {
        //let predicted_addr = self.peer_nat.predict_external_addr_from_local_bind_port(self.peer_unnated_listener_port).map(|r| SocketAddr::new(self.peer_remote_ip, r.port())).unwrap_or_else(|| SocketAddr::new(self.peer_remote_ip, self.peer_unnated_listener_port));
        let predicted_addr = self.peer_remote_addr_visible_from_server;
        // TODO: This assumes same IP, Port as visible from server. For EDM's w/delta,
        // we need to *ensure* the dualstack udp hole puncher can already handle deltas
        // properly
        let needs_turn = !self.peer_nat.stun_compatible(local_nat_type);
        (needs_turn, predicted_addr)
    }
}
