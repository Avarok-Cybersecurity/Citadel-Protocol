use crate::hdp::hdp_server::Ticket;
use hyxe_nat::udp_traversal::NatTraversalMethod;
use tokio::net::UdpSocket;
use crate::hdp::hdp_packet_processor::includes::Instant;
use crate::constants::DO_CONNECT_EXPIRE_TIME_MS;
use hyxe_nat::udp_traversal::linear::LinearUDPHolePuncher;
use hyxe_nat::hypernode_type::HyperNodeType;
use hyxe_nat::udp_traversal::hole_punched_udp_socket_addr::HolePunchedSocketAddr;
use hyxe_crypt::drill::Drill;

/// For keeping track of the pre-connect state
pub struct PreConnectState {
    pub(crate) last_stage: u8,
    pub(crate) adjacent_node_type: Option<HyperNodeType>,
    pub(crate) adjacent_unnated_ports: Option<Vec<u16>>,
    // This drill should be turned .into() the next toolset once the other side updated
    pub(crate) base_toolset_drill: Option<Drill>,
    pub(crate) reserved_sockets: Option<Vec<UdpSocket>>,
    pub(crate) hole_punched: Option<Vec<(UdpSocket, HolePunchedSocketAddr)>>,
    pub(crate) current_nat_traversal_method: Option<NatTraversalMethod>,
    pub(crate) ticket: Option<Ticket>,
    pub(crate) last_packet_time: Option<Instant>,
    pub(crate) hole_puncher: Option<LinearUDPHolePuncher>,
    pub(crate) nat_traversal_attempts: usize,
    pub(crate) success: bool
}

impl PreConnectState {
    /// This should be periodically called by the session event loop
    pub fn has_expired(&self) -> bool {
        if self.success {
            return false;
        }
        
        if let Some(prev_interaction) = self.last_packet_time.as_ref() {
            prev_interaction.elapsed() > DO_CONNECT_EXPIRE_TIME_MS
        } else {
            false
        }
    }

    pub fn on_packet_received(&mut self) {
        self.last_packet_time = Some(Instant::now());
    }
}

impl Default for PreConnectState {
    fn default() -> Self {
        Self { base_toolset_drill: None, hole_punched: None, hole_puncher: None, last_packet_time: None, reserved_sockets: None, adjacent_unnated_ports: None, last_stage: 0, adjacent_node_type: None, success: false, nat_traversal_attempts: 0, current_nat_traversal_method: None, ticket: None }
    }
}