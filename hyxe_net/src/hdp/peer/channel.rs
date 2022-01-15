use crate::hdp::hdp_server::{NodeRemote, Ticket, HdpServerRequest};
use hyxe_crypt::drill::SecurityLevel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::error::NetworkError;
use crate::hdp::state_container::{VirtualConnectionType, StateContainer};
use crate::hdp::outbound_sender::{UnboundedReceiver, OutboundUdpSender};
use futures::Stream;
use futures::task::{Context, Poll};
use tokio::macros::support::Pin;
use std::fmt::Debug;
use crate::hdp::peer::peer_layer::{PeerConnectionType, PeerSignal};
use hyxe_crypt::prelude::SecBuffer;
use crate::hdp::hdp_packet_processor::raw_primary_packet::ReceivePortType;
use crate::hdp::hdp_packet_crafter::SecureProtocolPacket;
use hyxe_user::re_imports::__private::Formatter;

// 1 peer channel per virtual connection. This enables high-level communication between the [HdpServer] and the API-layer.
#[derive(Debug)]
pub struct PeerChannel {
    send_half: PeerChannelSendHalf,
    recv_half: PeerChannelRecvHalf
}

impl PeerChannel {
    pub(crate) fn new(server_remote: NodeRemote, target_cid: u64, vconn_type: VirtualConnectionType, channel_id: Ticket, security_level: SecurityLevel, is_alive: Arc<AtomicBool>, receiver: UnboundedReceiver<SecBuffer>, state_container: StateContainer) -> Self {
        let implicated_cid = vconn_type.get_implicated_cid();
        let recv_type = ReceivePortType::OrderedReliable;

        let send_half = PeerChannelSendHalf {
            state_container,
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
            is_alive,
            recv_type
        };

        PeerChannel { send_half, recv_half }
    }

    /*
        pub(crate) fn new(server_remote: HdpServerRemote, target_cid: u64, vconn_type: VirtualConnectionType, channel_id: Ticket, security_level: SecurityLevel, is_alive: Arc<AtomicBool>, receiver: UnboundedReceiver<SecBuffer>, to_outbound: Sender<(Ticket, SecureProtocolPacket, VirtualTargetType, SecurityLevel)>) -> Self {
        let implicated_cid = vconn_type.get_implicated_cid();
        let recv_type = ReceivePortType::OrderedReliable;

        let send_half = PeerChannelSendHalf {
            tx: to_outbound,
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
            is_alive,
            recv_type
        };

        PeerChannel { send_half, recv_half }
    }
     */

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

/*
#[derive(Clone)]
pub struct PeerChannelSendHalf {
    tx: Sender<(Ticket, SecureProtocolPacket, VirtualTargetType, SecurityLevel)>,
    target_cid: u64,
    implicated_cid: u64,
    vconn_type: VirtualConnectionType,
    channel_id: Ticket,
    security_level: SecurityLevel,
    // When the associated virtual conn drops, this gets flipped off, and hence, data won't be sent anymore
    is_alive: Arc<AtomicBool>
}*/

#[derive(Clone)]
pub struct PeerChannelSendHalf {
    state_container: StateContainer,
    target_cid: u64,
    #[allow(dead_code)]
    implicated_cid: u64,
    vconn_type: VirtualConnectionType,
    channel_id: Ticket,
    security_level: SecurityLevel,
    // When the associated virtual conn drops, this gets flipped off, and hence, data won't be sent anymore
    is_alive: Arc<AtomicBool>
}

impl Debug for PeerChannelSendHalf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerChannel {:?}", self.vconn_type)
    }
}

impl PeerChannelSendHalf {
    pub fn set_security_level(&mut self, security_level: SecurityLevel) {
        self.security_level = security_level;
    }

    /// Sends a message using the sink interface
    pub async fn send_message(&mut self, message: SecureProtocolPacket) -> Result<(), NetworkError> {
        /*use futures::SinkExt;
        self.send(message).await*/
        let (ticket, message, v_conn, security_level) = self.get_args(message);
        inner_mut_state!(self.state_container).process_outbound_message(ticket, message, v_conn, security_level, false)?;
        //tokio::task::yield_now().await;
        Ok(())
    }

    /// used to identify this channel in the network
    pub fn channel_id(&self) -> Ticket {
        self.channel_id
    }

    #[allow(dead_code)]
    fn close(&self) {
        self.is_alive.store(false, Ordering::SeqCst);
    }

    /*
    /// Attempts to send, returning instantly if blocking would be required to send
    pub fn try_send(&mut self, message: SecureProtocolPacket) -> Result<(), SecureProtocolPacket> {
        let args = self.get_args(message);
        self.tx.try_send(args).map_err(|err| err.into_inner().1)
    }*/

    #[inline]
    fn get_args(&self, packet: SecureProtocolPacket) -> (Ticket, SecureProtocolPacket, VirtualConnectionType, SecurityLevel) {
        (self.channel_id, packet, self.vconn_type, self.security_level)
    }
}

/*
impl Sink<SecureProtocolPacket> for PeerChannelSendHalf {
    type Error = NetworkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.is_alive.load(Ordering::SeqCst) {
            Pin::new(&mut self.tx).poll_ready(cx).map_err(|err| NetworkError::Generic(err.to_string()))
        } else {
            Poll::Ready(Err(NetworkError::InternalError("Session closed")))
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: SecureProtocolPacket) -> Result<(), Self::Error> {
        let channel_id = self.channel_id;
        let target = self.vconn_type;
        let security_level = self.security_level;

        Pin::new(&mut self.tx).start_send((channel_id, item, target, security_level)).map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.tx).poll_flush(cx).map_err(|err| NetworkError::Generic(err.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.close();
        Pin::new(&mut self.tx).poll_close(cx).map_err(|err| NetworkError::Generic(err.to_string()))
    }
}*/

impl Unpin for PeerChannelRecvHalf {}

pub struct PeerChannelRecvHalf {
    // when the state container removes the vconn, this will get closed
    receiver: UnboundedReceiver<SecBuffer>,
    pub target_cid: u64,
    pub vconn_type: VirtualConnectionType,
    #[allow(dead_code)]
    channel_id: Ticket,
    is_alive: Arc<AtomicBool>,
    server_remote: NodeRemote,
    recv_type: ReceivePortType
}

impl Debug for PeerChannelRecvHalf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerChannel Rx {:?}", self.vconn_type)
    }
}

impl Stream for PeerChannelRecvHalf {
    type Item = SecBuffer;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.is_alive.load(Ordering::SeqCst) {
            // close the stream
            log::info!("[POLL] closing PeerChannel RecvHalf");
            Poll::Ready(None)
        } else {
            match futures::ready!(Pin::new(&mut self.receiver).poll_recv(cx)) {
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
                log::info!("[PeerChannelRecvHalf] Dropping. Will maybe set is_alive to false if this is a tcp p2p connection");

                let command = match self.recv_type {
                    ReceivePortType::OrderedReliable => {
                        self.is_alive.store(false, Ordering::SeqCst);
                        HdpServerRequest::PeerCommand(local_cid, PeerSignal::Disconnect(PeerConnectionType::HyperLANPeerToHyperLANPeer(local_cid, peer_cid), None))
                    }

                    ReceivePortType::UnorderedUnreliable => {
                        HdpServerRequest::PeerCommand(local_cid, PeerSignal::DisconnectUDP(self.vconn_type))
                    }
                };

                if let Err(err) = self.server_remote.try_send(command) {
                    log::warn!("[PeerChannelRecvHalf] unable to send stop signal to session: {:?}", err);
                }
            }

            _ => {
                // if c2s conn, we do nothing to allow the existence of the connection to continue
                // but, TODO: if one end drops, the other end shouldn't be allowed to send data, but at least still allow the c2s connection
            }
        }
    }
}

#[derive(Debug)]
pub struct UdpChannel {
    send_half: OutboundUdpSender,
    recv_half: PeerChannelRecvHalf
}

impl UdpChannel {
    pub fn new(send_half: OutboundUdpSender, receiver: UnboundedReceiver<SecBuffer>, target_cid: u64, vconn_type: VirtualConnectionType, channel_id: Ticket, is_alive: Arc<AtomicBool>, server_remote: NodeRemote) -> Self {
        Self {
            send_half,
            recv_half: PeerChannelRecvHalf {
                receiver,
                target_cid,
                vconn_type,
                channel_id,
                is_alive,
                server_remote,
                recv_type: ReceivePortType::UnorderedUnreliable
            }
        }
    }

    pub fn split(self) -> (OutboundUdpSender, PeerChannelRecvHalf) {
        (self.send_half, self.recv_half)
    }

    #[cfg(feature = "webrtc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "webrtc")))]
    pub fn into_webrtc_compat(self) -> WebRTCCompatChannel {
        self.into()
    }
}

#[cfg(feature = "webrtc")]
#[cfg_attr(docsrs, doc(cfg(feature = "webrtc")))]
pub struct WebRTCCompatChannel {
    send_half: OutboundUdpSender,
    recv_half: tokio::sync::Mutex<PeerChannelRecvHalf>
}

#[cfg(feature = "webrtc")]
mod rtc_impl {
    use async_trait::async_trait;
    use crate::hdp::hdp_packet_processor::includes::SocketAddr;
    use bytes::BytesMut;
    use crate::hdp::peer::channel::WebRTCCompatChannel;
    use crate::error::NetworkError;
    use crate::hdp::peer::channel::UdpChannel;

    impl From<UdpChannel> for WebRTCCompatChannel {
        fn from(this: UdpChannel) -> Self {
            Self { send_half: this.send_half, recv_half: tokio::sync::Mutex::new(this.recv_half) }
        }
    }

    #[async_trait]
    impl webrtc_util::Conn for WebRTCCompatChannel {
        async fn connect(&self, _addr: SocketAddr) -> Result<(), anyhow::Error> {
            // we assume we are already connected to the target addr by the time we get the UdpChannel
            Ok(())
        }

        async fn recv(&self, buf: &mut [u8]) -> Result<usize, anyhow::Error> {
            match self.recv_half.lock().await.receiver.recv().await {
                Some(input) => {
                    buf.copy_from_slice(input.as_ref());
                    Ok(input.len())
                }

                None => {
                    Err(NetworkError::InternalError("Stream ended").into())
                }
            }
        }

        async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), anyhow::Error> {
            let remote = self.send_half.remote_addr();
            let len = self.recv(buf).await?;
            Ok((len, remote))
        }

        async fn send(&self, buf: &[u8]) -> Result<usize, anyhow::Error> {
            self.send_half.unbounded_send(BytesMut::from(buf)).map_err(|err| NetworkError::Generic(err.into_string()))?;
            Ok(buf.len())
        }

        async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> Result<usize, anyhow::Error> {
            self.send(buf).await
        }

        async fn local_addr(&self) -> Result<SocketAddr, anyhow::Error> {
            Ok(self.send_half.local_addr())
        }

        async fn remote_addr(&self) -> Option<SocketAddr> {
            Some(self.send_half.remote_addr())
        }

        async fn close(&self) -> Result<(), anyhow::Error> {
            // the conn will automatically get closed on drop of recv half
            Ok(())
        }
    }
}