use crate::hdp::hdp_server::{HdpServerRemote, Ticket, HdpServerRequest};
use hyxe_crypt::drill::SecurityLevel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::error::NetworkError;
use crate::hdp::state_container::VirtualConnectionType;
use crate::hdp::outbound_sender::BoundedReceiver;
use futures::{Sink, Stream};
use futures::task::{Context, Poll};
use tokio::macros::support::Pin;
use std::fmt::Debug;
use crate::hdp::peer::peer_layer::{PeerConnectionType, PeerSignal};
use hyxe_crypt::sec_bytes::SecBuffer;

// 1 peer channel per virtual connection. This enables high-level communication between the [HdpServer] and the API-layer.
// This thus bypasses the kernel.
#[derive(Debug)]
pub struct PeerChannel {
    send_half: PeerChannelSendHalf,
    recv_half: PeerChannelRecvHalf
}

impl PeerChannel {
    pub(crate) fn new(server_remote: HdpServerRemote, target_cid: u64, vconn_type: VirtualConnectionType, channel_id: Ticket, security_level: SecurityLevel, is_alive: Arc<AtomicBool>, receiver: BoundedReceiver<SecBuffer>) -> Self {
        let implicated_cid = vconn_type.get_implicated_cid();

        let send_half = PeerChannelSendHalf {
            server_remote: server_remote.clone(),
            target_cid,
            vconn_type,
            implicated_cid,
            channel_id,
            security_level,
            is_alive: is_alive.clone()
        };

        let recv_half = PeerChannelRecvHalf {
            server_remote,
            receiver,
            target_cid,
            vconn_type,
            channel_id,
            is_alive
        };

        PeerChannel { send_half, recv_half }
    }

    /// Gets the CID of the endpoint
    pub fn get_peer_cid(&self) -> u64 {
        self.send_half.target_cid
    }

    /// Gets the CID of the local user
    pub fn get_implicated_cid(&self) -> u64 {
        self.send_half.vconn_type.get_implicated_cid()
    }

    /// Gets the metadata of the virtual connection
    pub fn get_peer_conn_type(&self) -> Option<PeerConnectionType> {
        self.send_half.vconn_type.try_as_peer_connection()
    }

    /// In order to use the [PeerChannel] properly, split must be called in order to receive
    /// an asynchronous interface. The SendHalf implements Sink, whereas the RecvHalf implements
    /// Stream
    pub fn split(self) -> (PeerChannelSendHalf, PeerChannelRecvHalf) {
        (self.send_half, self.recv_half)
    }
}

#[derive(Debug, Clone)]
pub struct PeerChannelSendHalf {
    server_remote: HdpServerRemote,
    target_cid: u64,
    implicated_cid: u64,
    vconn_type: VirtualConnectionType,
    channel_id: Ticket,
    security_level: SecurityLevel,
    // When the associated virtual conn drops, this gets flipped off, and hence, data won't be sent anymore
    is_alive: Arc<AtomicBool>
}

impl PeerChannelSendHalf {
    pub fn set_security_level(&mut self, security_level: SecurityLevel) {
        self.security_level = security_level;
    }

    /// Sends a message using the sink interface
    pub async fn send_message(&mut self, message: SecBuffer) -> Result<(), NetworkError> {
        use futures::SinkExt;
        self.send(message).await
    }

    /// used to identify this channel in the network
    pub fn channel_id(&self) -> Ticket {
        self.channel_id
    }

    fn close(&self) {
        self.is_alive.store(false, Ordering::SeqCst);
    }
}

impl Sink<SecBuffer> for PeerChannelSendHalf {
    type Error = NetworkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.is_alive.load(Ordering::SeqCst) {
            futures::Sink::<HdpServerRequest>::poll_ready(Pin::new(&mut self.server_remote), cx)
        } else {
            Poll::Ready(Err(NetworkError::InternalError("Server closed")))
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: SecBuffer) -> Result<(), Self::Error> {
        let channel_id = self.channel_id;
        let item = HdpServerRequest::SendMessage(item, self.implicated_cid, self.vconn_type, self.security_level);

        Pin::new(&mut self.server_remote).start_send((channel_id, item))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

impl Unpin for PeerChannelRecvHalf {}

#[derive(Debug)]
pub struct PeerChannelRecvHalf {
    // when the state container removes the vconn, this will get closed
    receiver: BoundedReceiver<SecBuffer>,
    target_cid: u64,
    vconn_type: VirtualConnectionType,
    channel_id: Ticket,
    is_alive: Arc<AtomicBool>,
    server_remote: HdpServerRemote
}

impl Stream for PeerChannelRecvHalf {
    type Item = SecBuffer;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.is_alive.load(Ordering::SeqCst) {
            // close the stream
            log::info!("[POLL] closing PeerChannel RecvHalf");
            Poll::Ready(None)
        } else {
            match futures::ready!(Pin::new(&mut self.receiver).poll_next(cx)) {
                Some(data) => Poll::Ready(Some(data)),
                _ => {
                    log::info!("[PeerChannelRecvHalf] ending");
                    Poll::Ready(None)
                }
            }
        }
    }
}

impl Drop for PeerChannelRecvHalf {
    fn drop(&mut self) {
        match self.vconn_type {
            VirtualConnectionType::HyperLANPeerToHyperLANPeer(local_cid, peer_cid) => {
                log::info!("[PeerChannelRecvHalf] Dropping. Will set is_alive to false since this is a p2p connection");
                self.is_alive.store(false, Ordering::SeqCst);

                if let Err(err) = self.server_remote.try_send(HdpServerRequest::PeerCommand(local_cid, PeerSignal::Disconnect(PeerConnectionType::HyperLANPeerToHyperLANPeer(local_cid, peer_cid), None))) {
                    log::warn!("[PeerChannelRecvHalf] unable to send stop signal to session: {:?}", err);
                }

            }

            _ => {}
        }
    }
}