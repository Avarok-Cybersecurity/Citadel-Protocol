//! # Peer Channel Management
//!
//! This module implements the communication channels between peers in the Citadel Protocol.
//! It provides both TCP and UDP channel implementations with support for secure message passing
//! and WebRTC compatibility.
//!
//! ## Features
//!
//! - **Split Channel Architecture**: Separate send and receive halves for async operations
//! - **Security Level Control**: Configurable security levels for message encryption
//! - **UDP Support**: Dedicated UDP channel implementation for performance
//! - **WebRTC Compatibility**: Optional WebRTC support via feature flag
//! - **Resource Cleanup**: Automatic cleanup on channel drop
//! - **Stream Interface**: Implements Stream trait for async message reception
//! - **Virtual Connection Management**: Supports multiple virtual connections per peer
//!
//! ## Example Usage
//!
//! ```no_run
//! use citadel_proto::prelude::*;
//! use futures::StreamExt;
//! use citadel_types::crypto::SecurityLevel;
//! use citadel_crypt::ratchets::stacked::StackedRatchet;
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//!
//! # let channel: PeerChannel<StackedRatchet> = todo!();
//! // Split into send and receive halves
//! let (mut send_half, recv_half) = channel.split();
//!
//! // Send a message
//! send_half.send("Hello, world!").await?;
//!
//! // Receive messages asynchronously
//! while let Some(message) = recv_half.next().await {
//!     // Process received message
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Important Notes
//!
//! - Channel drops trigger automatic peer disconnection for P2P connections
//! - WebRTC support requires the "webrtc" feature flag
//! - Channels maintain their own security level settings
//! - UDP channels provide optional WebRTC compatibility layer
//!
//! ## Related Components
//!
//! - [`peer_layer`]: Manages peer connections and routing
//! - [`session`]: Handles session state and management
//! - [`state_container`]: Maintains virtual connection state
//! - [`packet_processor`]: Processes incoming and outgoing packets
//!

use crate::error::NetworkError;
use crate::proto::node_request::{NodeRequest, PeerCommand};
use crate::proto::outbound_sender::{OutboundUdpSender, UnboundedReceiver};
use crate::proto::peer::peer_layer::{PeerConnectionType, PeerSignal};
use crate::proto::remote::{NodeRemote, Ticket};
use crate::proto::session::UserMessage;
use crate::proto::state_container::VirtualConnectionType;
use crate::{ProtocolMessenger, ProtocolMessengerRx, ProtocolMessengerTx};
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::macros::support::Pin;
use citadel_types::crypto::SecBuffer;
use citadel_types::crypto::SecurityLevel;
use citadel_user::re_exports::__private::Formatter;
use futures::task::{Context, Poll};
use futures::Stream;
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// 1 peer channel per virtual connection. This enables high-level communication between the [HdpServer] and the API-layer.
#[derive(Debug)]
pub struct PeerChannel<R: Ratchet> {
    send_half: PeerChannelSendHalf<R>,
    recv_half: PeerChannelRecvHalf<R>,
}

impl<R: Ratchet> PeerChannel<R> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        node_remote: NodeRemote<R>,
        target_cid: u64,
        vconn_type: VirtualConnectionType,
        channel_id: Ticket,
        security_level: SecurityLevel,
        is_alive: Arc<AtomicBool>,
        messenger: ProtocolMessenger<R>,
    ) -> Self {
        let session_cid = vconn_type.get_session_cid();

        let (to_outbound_stream, from_inbound_stream) = messenger.split();

        let send_half = PeerChannelSendHalf {
            to_outbound_stream,
            target_cid,
            vconn_type,
            session_cid,
            channel_id,
            security_level,
        };

        let recv_half = PeerChannelRecvHalf {
            node_remote,
            receiver: ReceiverType::OrderedReliable {
                rx: from_inbound_stream,
            },
            target_cid,
            vconn_type,
            channel_id,
            is_alive,
        };

        PeerChannel {
            send_half,
            recv_half,
        }
    }

    /// Gets the CID of the endpoint
    pub fn get_peer_cid(&self) -> u64 {
        self.send_half.target_cid
    }

    /// Gets the CID of the local user
    pub fn get_session_cid(&self) -> u64 {
        self.send_half.vconn_type.get_session_cid()
    }

    /// Gets the metadata of the virtual connection
    pub fn get_peer_conn_type(&self) -> Option<PeerConnectionType> {
        self.send_half.vconn_type.try_as_peer_connection()
    }

    /// In order to use the [PeerChannel] properly, split must be called in order to receive
    /// an asynchronous interface. The SendHalf implements Sink, whereas the RecvHalf implements
    /// Stream
    pub fn split(self) -> (PeerChannelSendHalf<R>, PeerChannelRecvHalf<R>) {
        (self.send_half, self.recv_half)
    }
}

pub struct PeerChannelSendHalf<R: Ratchet> {
    to_outbound_stream: ProtocolMessengerTx<R>,
    target_cid: u64,
    #[allow(dead_code)]
    session_cid: u64,
    vconn_type: VirtualConnectionType,
    channel_id: Ticket,
    security_level: SecurityLevel,
}

impl<R: Ratchet> Debug for PeerChannelSendHalf<R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerChannel {:?}", self.vconn_type)
    }
}

impl<R: Ratchet> PeerChannelSendHalf<R> {
    pub fn set_security_level(&mut self, security_level: SecurityLevel) {
        self.security_level = security_level;
    }

    /// Sends a message through the channel
    pub async fn send<T: Into<SecBuffer>>(&mut self, message: T) -> Result<(), NetworkError> {
        let request = UserMessage {
            ticket: self.channel_id,
            packet: message.into(),
            target: self.vconn_type,
            security_level: self.security_level,
        };

        self.to_outbound_stream
            .send(request)
            .await
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    /// used to identify this channel in the network
    pub fn channel_id(&self) -> Ticket {
        self.channel_id
    }
}

impl<R: Ratchet> Unpin for PeerChannelRecvHalf<R> {}

/// A stream interface for receiving secure packets
/// NOTE: on drop, if this is used for a P2P connection, disconnection
/// will occur
pub struct PeerChannelRecvHalf<R: Ratchet> {
    // when the state container removes the vconn, this will get closed
    receiver: ReceiverType<R>,
    pub target_cid: u64,
    pub vconn_type: VirtualConnectionType,
    #[allow(dead_code)]
    channel_id: Ticket,
    is_alive: Arc<AtomicBool>,
    node_remote: NodeRemote<R>,
}

enum ReceiverType<R: Ratchet> {
    OrderedReliable { rx: ProtocolMessengerRx<R> },
    UnorderedUnreliable { rx: UnboundedReceiver<SecBuffer> },
}

impl<R: Ratchet> Stream for ReceiverType<R> {
    type Item = SecBuffer;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            ReceiverType::OrderedReliable { rx } => {
                match futures::ready!(Pin::new(rx).poll_next(cx)) {
                    Some(data) => Poll::Ready(Some(data.packet)),
                    _ => {
                        log::trace!(target: "citadel", "[PeerChannelRecvHalf] ending for OrderedReliable");
                        Poll::Ready(None)
                    }
                }
            }

            ReceiverType::UnorderedUnreliable { rx } => {
                match futures::ready!(Pin::new(rx).poll_recv(cx)) {
                    Some(data) => Poll::Ready(Some(data)),
                    _ => {
                        log::trace!(target: "citadel", "[PeerChannelRecvHalf] ending for UnorderedUnreliable");
                        Poll::Ready(None)
                    }
                }
            }
        }
    }
}

impl<R: Ratchet> Debug for ReceiverType<R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let receiver_type = match self {
            Self::OrderedReliable { .. } => "OrderedReliable",
            Self::UnorderedUnreliable { .. } => "UnorderedUnreliable",
        };
        write!(f, "{receiver_type}")
    }
}

impl<R: Ratchet> Debug for PeerChannelRecvHalf<R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerChannel Rx {:?}", self.vconn_type)
    }
}

impl<R: Ratchet> Stream for PeerChannelRecvHalf<R> {
    type Item = SecBuffer;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.is_alive.load(Ordering::SeqCst) {
            // close the stream
            log::trace!(target: "citadel", "[POLL] closing PeerChannel RecvHalf for {:?}", self.receiver);
            Poll::Ready(None)
        } else {
            Pin::new(&mut self.receiver).poll_next(cx)
        }
    }
}

impl<R: Ratchet> Drop for PeerChannelRecvHalf<R> {
    fn drop(&mut self) {
        if let VirtualConnectionType::LocalGroupPeer {
            session_cid: local_cid,
            peer_cid,
        } = self.vconn_type
        {
            log::trace!(target: "citadel", "[PeerChannelRecvHalf] Dropping {:?} type. Will maybe set is_alive to false if this is a tcp p2p connection", self.receiver);

            let command = match &self.receiver {
                ReceiverType::OrderedReliable { .. } => {
                    self.is_alive.store(false, Ordering::SeqCst);
                    NodeRequest::PeerCommand(PeerCommand {
                        session_cid: local_cid,
                        command: PeerSignal::Disconnect {
                            peer_conn_type: PeerConnectionType::LocalGroupPeer {
                                session_cid: local_cid,
                                peer_cid,
                            },
                            disconnect_response: None,
                        },
                    })
                }

                ReceiverType::UnorderedUnreliable { .. } => {
                    if let Some(peer_conn_type) = self.vconn_type.try_as_peer_connection() {
                        NodeRequest::PeerCommand(PeerCommand {
                            session_cid: local_cid,
                            command: PeerSignal::DisconnectUDP { peer_conn_type },
                        })
                    } else {
                        log::error!(target: "citadel", "Unable to convert v_conn_type to peer_conn_type. This is a bug");
                        return;
                    }
                }
            };

            if let Err(err) = self.node_remote.try_send(command) {
                log::warn!(target: "citadel", "[PeerChannelRecvHalf] unable to send stop signal to session: {err:?}");
            }
        }
    }
}

#[derive(Debug)]
pub struct UdpChannel<R: Ratchet> {
    send_half: OutboundUdpSender,
    recv_half: PeerChannelRecvHalf<R>,
}

impl<R: Ratchet> UdpChannel<R> {
    pub fn new(
        send_half: OutboundUdpSender,
        rx: UnboundedReceiver<SecBuffer>,
        target_cid: u64,
        vconn_type: VirtualConnectionType,
        channel_id: Ticket,
        is_alive: Arc<AtomicBool>,
        node_remote: NodeRemote<R>,
    ) -> Self {
        Self {
            send_half,
            recv_half: PeerChannelRecvHalf {
                receiver: ReceiverType::UnorderedUnreliable { rx },
                target_cid,
                vconn_type,
                channel_id,
                is_alive,
                node_remote,
            },
        }
    }

    pub fn split(self) -> (OutboundUdpSender, PeerChannelRecvHalf<R>) {
        (self.send_half, self.recv_half)
    }

    #[cfg(feature = "webrtc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "webrtc")))]
    pub fn into_webrtc_compat(self) -> WebRTCCompatChannel<R> {
        self.into()
    }
}

#[cfg(feature = "webrtc")]
#[cfg_attr(docsrs, doc(cfg(feature = "webrtc")))]
pub struct WebRTCCompatChannel<R: Ratchet> {
    send_half: OutboundUdpSender,
    recv_half: citadel_io::tokio::sync::Mutex<PeerChannelRecvHalf<R>>,
}

#[cfg(feature = "webrtc")]
mod rtc_impl {
    use crate::proto::packet_processor::includes::SocketAddr;
    use crate::proto::peer::channel::UdpChannel;
    use crate::proto::peer::channel::WebRTCCompatChannel;
    use async_trait::async_trait;
    use bytes::BytesMut;
    use citadel_crypt::ratchets::Ratchet;
    use futures::StreamExt;

    impl<R: Ratchet> From<UdpChannel<R>> for WebRTCCompatChannel<R> {
        fn from(this: UdpChannel<R>) -> Self {
            Self {
                send_half: this.send_half,
                recv_half: citadel_io::tokio::sync::Mutex::new(this.recv_half),
            }
        }
    }

    #[async_trait]
    impl<R: Ratchet> webrtc_util::Conn for WebRTCCompatChannel<R> {
        async fn connect(&self, _addr: SocketAddr) -> Result<(), webrtc_util::Error> {
            // we assume we are already connected to the target addr by the time we get the UdpChannel
            Ok(())
        }

        async fn recv(&self, buf: &mut [u8]) -> Result<usize, webrtc_util::Error> {
            match self.recv_half.lock().await.receiver.next().await {
                Some(input) => {
                    buf.copy_from_slice(input.as_ref());
                    Ok(input.len())
                }

                None => Err(webrtc_util::Error::Other(
                    "WebRTC Receiver stream ended".to_string(),
                )),
            }
        }

        async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> Result<(usize, SocketAddr), webrtc_util::Error> {
            let remote = self.send_half.remote_addr();
            let len = self.recv(buf).await?;
            Ok((len, remote))
        }

        async fn send(&self, buf: &[u8]) -> Result<usize, webrtc_util::Error> {
            self.send_half
                .unbounded_send(BytesMut::from(buf))
                .map_err(|err| webrtc_util::Error::Other(err.into_string()))?;
            Ok(buf.len())
        }

        async fn send_to(
            &self,
            buf: &[u8],
            _target: SocketAddr,
        ) -> Result<usize, webrtc_util::Error> {
            self.send(buf).await
        }

        fn local_addr(&self) -> Result<SocketAddr, webrtc_util::Error> {
            Ok(self.send_half.local_addr())
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(self.send_half.remote_addr())
        }

        async fn close(&self) -> Result<(), webrtc_util::Error> {
            // the conn will automatically get closed on drop of recv half
            Ok(())
        }

        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync + 'static) {
            self
        }
    }
}
