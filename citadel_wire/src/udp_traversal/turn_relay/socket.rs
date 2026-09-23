//! A TURN allocation presented to quinn as a UDP socket, so QUIC runs unchanged over the relay.
//!
//! quinn addresses the peer by its transport address as the TURN server sees it; this socket maps
//! that address to the bound channel (or a Send indication) on the way out and back from the
//! channel / Data indication on the way in. The local address it reports is the relayed address.

use std::fmt::{Debug, Formatter};
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use super::client::TurnAllocation;

pub struct TurnRelaySocket {
    allocation: Arc<TurnAllocation>,
}

impl TurnRelaySocket {
    pub fn new(allocation: Arc<TurnAllocation>) -> Self {
        Self { allocation }
    }

    pub fn allocation(&self) -> &Arc<TurnAllocation> {
        &self.allocation
    }
}

impl Debug for TurnRelaySocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TurnRelaySocket")
            .field(&self.allocation)
            .finish()
    }
}

/// Sends never block: the allocation's outbound queue sheds on overflow, like a congested socket.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for TurnRelaySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // max_transmit_segments() is 1, so quinn never hands over a GSO batch.
        self.allocation
            .send_to(transmit.destination, transmit.contents)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut filled = 0;
        while filled < bufs.len().min(meta.len()) {
            let next = if filled == 0 {
                match self.allocation.poll_recv_from(cx) {
                    Poll::Ready(Ok(d)) => d,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match self.allocation.try_recv_from() {
                    Some(d) => d,
                    None => break,
                }
            };
            let (from, payload) = next;
            let len = payload.len().min(bufs[filled].len());
            bufs[filled][..len].copy_from_slice(&payload[..len]);
            meta[filled] = RecvMeta {
                addr: from,
                len,
                stride: len,
                ecn: None,
                dst_ip: None,
            };
            filled += 1;
        }
        Poll::Ready(Ok(filled))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.allocation.relayed_addr())
    }

    /// The client leg to the TURN server does not set DF, so path-MTU probing through the relay
    /// would measure nothing; quinn keeps the relayed MTU fixed (see `quic::RELAYED_QUIC_MTU`).
    fn may_fragment(&self) -> bool {
        true
    }
}
