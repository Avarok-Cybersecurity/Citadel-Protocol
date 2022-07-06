use crate::hdp::outbound_sender::{UnboundedReceiver, OutboundPrimaryStreamSender};
use bytes::Bytes;
use std::net::SocketAddr;
use netbeam::reliable_conn::{ReliableOrderedStreamToTarget, ConnAddr};
use tokio::sync::Mutex;
use crate::hdp::state_container::StateContainerInner;
use hyxe_crypt::stacked_ratchet::StackedRatchet;
use hyxe_crypt::drill::SecurityLevel;
use async_trait::async_trait;
use crate::hdp::peer::p2p_conn_handler::generic_error;
use std::str::FromStr;

pub(crate) struct ReliableOrderedCompatStream {
    to_primary_stream: OutboundPrimaryStreamSender,
    from_stream: Mutex<UnboundedReceiver<Bytes>>,
    peer_external_addr: SocketAddr,
    local_bind_addr: SocketAddr,
    hr: StackedRatchet,
    security_level: SecurityLevel,
    target_cid: u64
}

impl ReliableOrderedCompatStream {
    /// For C2S, using this is straight forward (set target_cid to 0)
    /// For P2P, using this is not as straight forward. This will use the central node for routing packets. As such, the target_cid must be set to the peers to enable routing. Additionally, this will need to use the p2p ratchet. This implies that
    /// BOTH nodes must already have the ratchets loaded
    pub(crate) fn new(to_primary_stream: OutboundPrimaryStreamSender, state_container: &mut StateContainerInner, target_cid: u64, hr: StackedRatchet, security_level: SecurityLevel) -> Self {
        let (from_stream_tx, from_stream_rx) = tokio::sync::mpsc::unbounded_channel();

        // insert from_stream_tx into state container so that the protocol can deliver packets to the hole puncher
        // NOTE: The protocol must strip the header when passing packets to the from_stream function!
        let _ = state_container.hole_puncher_pipes.insert(target_cid, from_stream_tx);
        // NOTE: this is hacky. We don't actually need real addrs here since this is used for hole punching
        let peer_external_addr = SocketAddr::from_str("1.2.3.4:1234").unwrap();
        let local_bind_addr = SocketAddr::from_str("0.0.0.0:1234").unwrap();
        Self { to_primary_stream, from_stream: Mutex::new(from_stream_rx), peer_external_addr, local_bind_addr, hr, security_level, target_cid }
    }
}

#[async_trait]
impl ReliableOrderedStreamToTarget for ReliableOrderedCompatStream {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        let packet = crate::hdp::hdp_packet_crafter::hole_punch::generate_packet(&self.hr, input, self.security_level, self.target_cid);
        self.to_primary_stream.unbounded_send(packet).map_err(|err| generic_error(err.to_string()))
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        // This assumes the payload is stripped from the header and the payload is decrypted
        // packet is decrypted in hole_punch.rs
        log::trace!(target: "lusna", "attempting to recv");
        self.from_stream.lock().await.recv().await.ok_or_else(|| generic_error("Inbound ordered reliable stream died"))
    }
}

impl ConnAddr for ReliableOrderedCompatStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_bind_addr)
    }
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer_external_addr)
    }
}