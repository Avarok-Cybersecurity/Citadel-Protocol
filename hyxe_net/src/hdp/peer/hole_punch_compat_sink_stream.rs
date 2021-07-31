use crate::hdp::outbound_sender::{UnboundedSender, UnboundedReceiver};
use bytes::{BytesMut, Bytes};
use std::net::SocketAddr;
use hyxe_nat::reliable_conn::ReliableOrderedConnectionToTarget;
use parking_lot::Mutex;
use crate::hdp::state_container::StateContainerInner;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_crypt::drill::SecurityLevel;

pub(crate) struct HolePunchCompatStream {
    to_stream: Box<dyn for<'a> Fn(&'a [u8]) -> Result<(), anyhow::Error>>,
    from_stream: Mutex<UnboundedReceiver<Bytes>>,
    peer_external_addr: SocketAddr,
    local_bind_addr: SocketAddr
}

impl HolePunchCompatStream {
    pub(crate) fn new(to_primary_stream: UnboundedSender<BytesMut>, state_container: &mut StateContainerInner, peer_external_addr: SocketAddr, local_bind_addr: SocketAddr, target_cid: u64, ref hyper_ratchet: HyperRatchet, security_level: SecurityLevel) -> Self {
        let (from_stream_tx, from_stream_rx) = tokio::sync::mpsc::unbounded_channel();

        let to_stream = Box::new(move |packet| {
            let packet = crate::hdp::hdp_packet_crafter::hole_punch::generate_packet(hyper_ratchet, packet, security_level, target_cid);
            Ok(to_primary_stream.unbounded_send(packet)?)
        });

        // insert from_stream_tx into state container so that the protocol can deliver packets to the hole puncher
        // NOTE: The protocol must strip the header when passing packets to the from_stream function!
        let _ = state_container.hole_puncher_pipes.insert(target_cid, from_stream_tx);

        Self { to_stream, from_stream: Mutex::new(from_stream_rx), peer_external_addr, local_bind_addr }
    }
}

impl ReliableOrderedConnectionToTarget for HolePunchCompatStream {
    async fn send_to_peer(&self, input: &[u8]) -> Result<(), anyhow::Error> {
        (self.to_stream)(input)
    }

    async fn recv(&self) -> Result<Bytes, anyhow::Error> {
        // This assumes the payload is stripped from the header and the payload is decrypted
        Ok(self.from_stream.lock().recv().await.ok_or_else(|| anyhow::Error::msg("Inbound ordered reliable stream died"))?)
    }

    fn local_addr(&self) -> Result<SocketAddr, anyhow::Error> {
        Ok(self.local_bind_addr)
    }

    fn peer_addr(&self) -> Result<SocketAddr, anyhow::Error> {
        Ok(self.peer_external_addr)
    }
}
