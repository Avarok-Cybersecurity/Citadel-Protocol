use crate::hdp::hdp_server::Ticket;
use hyxe_nat::udp_traversal::NatTraversalMethod;
use crate::hdp::hdp_packet_processor::includes::Instant;
use crate::constants::DO_CONNECT_EXPIRE_TIME_MS;
use hyxe_nat::udp_traversal::linear::LinearUDPHolePuncher;
use hyxe_nat::hypernode_type::HyperNodeType;
use hyxe_nat::udp_traversal::hole_punched_udp_socket_addr::HolePunchedUdpSocket;
use hyxe_crypt::hyper_ratchet::constructor::HyperRatchetConstructor;
use tokio::sync::oneshot::{Sender, Receiver, channel};
use crate::hdp::peer::channel::UdpChannel;

/// For keeping track of the pre-connect state
pub struct PreConnectState {
    pub(crate) last_stage: u8,
    #[allow(dead_code)]
    pub(crate) adjacent_node_type: Option<HyperNodeType>,
    // This drill should be turned .into() the next toolset once the other side updated
    pub(crate) constructor: Option<HyperRatchetConstructor>,
    pub(crate) hole_punched: Option<HolePunchedUdpSocket>,
    pub(crate) current_nat_traversal_method: Option<NatTraversalMethod>,
    pub(crate) ticket: Option<Ticket>,
    pub(crate) last_packet_time: Option<Instant>,
    pub(crate) hole_puncher: Option<LinearUDPHolePuncher>,
    pub(crate) udp_channel_oneshot_tx: UdpChannelSender,
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
        Self { udp_channel_oneshot_tx: UdpChannelSender::empty(), constructor: None, hole_punched: None, hole_puncher: None, last_packet_time: None, last_stage: 0, adjacent_node_type: None, success: false, nat_traversal_attempts: 0, current_nat_traversal_method: None, ticket: None }
    }
}

pub struct UdpChannelSender {
    pub tx: Option<Sender<UdpChannel>>,
    pub rx: Option<Receiver<UdpChannel>>
}

impl UdpChannelSender {
    pub(crate) fn empty() -> Self {
        Self { tx: None, rx: None }
    }
}

impl Default for UdpChannelSender {
    fn default() -> Self {
        let (tx, rx) = channel();
        Self { tx: Some(tx), rx: Some(rx) }
    }
}