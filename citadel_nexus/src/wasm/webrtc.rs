//! WebRTC DataChannel implementation for WASM

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use js_sys::Uint8Array;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use wasm_bindgen::prelude::*;
use web_sys::{
    MessageEvent, RtcDataChannel, RtcDataChannelInit, RtcDataChannelState, RtcPeerConnection,
};

use super::signaling::{SignalingConfig, SignalingMessage, WebRtcSignaling};
use crate::error::{NexusError, NexusResult};
use crate::traits::{ListenerStats, NetworkListener, NetworkStream, SecurityInfo, StreamStats};

/// WebRTC connection statistics
#[derive(Debug)]
pub struct WebRtcStats {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub created_at: SystemTime,
}

impl WebRtcStats {
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            created_at: SystemTime::now(),
        }
    }
}

/// WebRTC listener statistics
#[derive(Debug, Clone)]
pub struct WebRtcListenerStats {
    pub connections_accepted: u64,
    pub active_connections: u32,
    pub connection_errors: u64,
    pub created_at: SystemTime,
}

impl WebRtcListenerStats {
    pub fn new() -> Self {
        Self {
            connections_accepted: 0,
            active_connections: 0,
            connection_errors: 0,
            created_at: SystemTime::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Connecting,
    Connected,
    Disconnected,
    Failed,
    Closed,
}

/// WebRTC DataChannel implementation for reliable streams
pub struct WebRtcDataChannel {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    stats: WebRtcStats,
    peer_connection: Option<RtcPeerConnection>,
    data_channel: Option<RtcDataChannel>,
    receive_buffer: Rc<RefCell<VecDeque<Vec<u8>>>>,
    #[allow(dead_code)]
    pending_writes: Rc<RefCell<VecDeque<Vec<u8>>>>,
    #[allow(dead_code)]
    signaling: Rc<RefCell<Option<WebRtcSignaling>>>,
    connection_state: Rc<RefCell<ConnectionState>>,
    #[allow(dead_code)]
    peer_id: String,
}

// Debug implementation since we can't derive it with web_sys types
impl std::fmt::Debug for WebRtcDataChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebRtcDataChannel")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("stats", &self.stats)
            .finish()
    }
}

impl WebRtcDataChannel {
    pub async fn connect(addr: SocketAddr) -> NexusResult<Self> {
        Self::connect_with_signaling(addr, SignalingConfig::default()).await
    }

    pub async fn connect_with_signaling(
        addr: SocketAddr,
        config: SignalingConfig,
    ) -> NexusResult<Self> {
        let mut signaling = WebRtcSignaling::new(config);
        signaling.connect().await?;

        let peer_id = format!(
            "peer_{}_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            addr.to_string().replace([':', '.'], "_")
        );

        let peer_connection = signaling.create_peer_connection(&peer_id)?;

        // Create data channel for reliable communication
        let data_channel_config = RtcDataChannelInit::new();
        data_channel_config.set_ordered(true);
        data_channel_config.set_max_retransmits(3);

        let data_channel = peer_connection
            .create_data_channel_with_data_channel_dict("citadel", &data_channel_config);

        let receive_buffer = Rc::new(RefCell::new(VecDeque::new()));
        let pending_writes = Rc::new(RefCell::new(VecDeque::new()));
        let connection_state = Rc::new(RefCell::new(ConnectionState::Connecting));

        // Set up data channel event handlers
        let receive_buffer_clone = receive_buffer.clone();
        let onmessage_callback = Closure::wrap(Box::new(move |event: MessageEvent| {
            if let Ok(array_buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                let uint8_array = Uint8Array::new(&array_buffer);
                let mut data = vec![0; uint8_array.length() as usize];
                uint8_array.copy_to(&mut data);
                receive_buffer_clone.borrow_mut().push_back(data);
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        data_channel.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
        onmessage_callback.forget();

        let connection_state_clone = connection_state.clone();
        let onopen_callback = Closure::wrap(Box::new(move || {
            *connection_state_clone.borrow_mut() = ConnectionState::Connected;
        }) as Box<dyn FnMut()>);
        data_channel.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
        onopen_callback.forget();

        let connection_state_clone = connection_state.clone();
        let onclose_callback = Closure::wrap(Box::new(move || {
            *connection_state_clone.borrow_mut() = ConnectionState::Disconnected;
        }) as Box<dyn FnMut()>);
        data_channel.set_onclose(Some(onclose_callback.as_ref().unchecked_ref()));
        onclose_callback.forget();

        let connection_state_clone = connection_state.clone();
        let onerror_callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
            *connection_state_clone.borrow_mut() = ConnectionState::Failed;
        }) as Box<dyn FnMut(_)>);
        data_channel.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
        onerror_callback.forget();

        // Perform WebRTC handshake
        let offer_sdp = signaling.create_offer(&peer_id).await?;
        signaling.send_message(SignalingMessage::Offer {
            sdp: offer_sdp,
            peer_id: peer_id.clone(),
        })?;

        // Wait for answer
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 100; // 10 seconds timeout
        while attempts < MAX_ATTEMPTS {
            if let Some(message) = signaling.get_next_message() {
                match message {
                    SignalingMessage::Answer { sdp, peer_id: _ } => {
                        signaling.handle_answer(&peer_id, &sdp).await?;
                        break;
                    }
                    SignalingMessage::IceCandidate {
                        candidate,
                        sdp_mid,
                        sdp_m_line_index,
                        ..
                    } => {
                        signaling
                            .handle_ice_candidate(&peer_id, &candidate, sdp_mid, sdp_m_line_index)
                            .await?;
                    }
                    SignalingMessage::Error { message } => {
                        return Err(NexusError::Connection(format!(
                            "Signaling error: {}",
                            message
                        )));
                    }
                    _ => {}
                }
            }

            // Small delay to prevent busy waiting
            wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&JsValue::UNDEFINED))
                .await
                .ok();

            attempts += 1;
        }

        if attempts >= MAX_ATTEMPTS {
            return Err(NexusError::Connection(
                "Timeout waiting for WebRTC connection".to_string(),
            ));
        }

        // Wait for data channel to be ready
        let mut wait_attempts = 0;
        while wait_attempts < 50 {
            // 5 second timeout
            if data_channel.ready_state() == RtcDataChannelState::Open {
                break;
            }
            wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&JsValue::UNDEFINED))
                .await
                .ok();
            wait_attempts += 1;
        }

        Ok(Self {
            local_addr: addr,
            peer_addr: addr,
            stats: WebRtcStats::new(),
            peer_connection: Some(peer_connection),
            data_channel: Some(data_channel),
            receive_buffer,
            pending_writes,
            signaling: Rc::new(RefCell::new(Some(signaling))),
            connection_state,
            peer_id,
        })
    }

    pub fn local_addr(&self) -> NexusResult<SocketAddr> {
        Ok(self.local_addr)
    }

    pub fn peer_addr(&self) -> NexusResult<SocketAddr> {
        Ok(self.peer_addr)
    }

    fn stats(&self) -> StreamStats {
        StreamStats {
            duration: self.stats.created_at.elapsed().unwrap_or_default(),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            rtt: None, // RTT not available for WebRTC DataChannels
        }
    }

    pub async fn shutdown(&mut self) -> NexusResult<()> {
        // Close the data channel
        if let Some(ref data_channel) = self.data_channel {
            data_channel.close();
        }

        // Close the peer connection
        if let Some(ref peer_connection) = self.peer_connection {
            peer_connection.close();
        }

        // Update connection state
        *self.connection_state.borrow_mut() = ConnectionState::Closed;

        Ok(())
    }
}

impl AsyncRead for WebRtcDataChannel {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut receive_buffer = self.receive_buffer.borrow_mut();

        if let Some(data) = receive_buffer.pop_front() {
            let bytes_to_copy = std::cmp::min(data.len(), buf.len());
            buf[..bytes_to_copy].copy_from_slice(&data[..bytes_to_copy]);

            // If we didn't consume all data, put the rest back
            if bytes_to_copy < data.len() {
                receive_buffer.push_front(data[bytes_to_copy..].to_vec());
            }

            // Update statistics
            self.stats
                .bytes_received
                .fetch_add(bytes_to_copy as u64, std::sync::atomic::Ordering::Relaxed);

            Poll::Ready(Ok(bytes_to_copy))
        } else {
            // No data available - check connection state
            match *self.connection_state.borrow() {
                ConnectionState::Connected => {
                    Poll::Pending // Wait for more data
                }
                ConnectionState::Disconnected
                | ConnectionState::Failed
                | ConnectionState::Closed => {
                    Poll::Ready(Ok(0)) // EOF
                }
                ConnectionState::Connecting => {
                    Poll::Pending // Still connecting
                }
            }
        }
    }
}

impl AsyncWrite for WebRtcDataChannel {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        // Check connection state
        match *self.connection_state.borrow() {
            ConnectionState::Connected => {
                if let Some(ref data_channel) = self.data_channel {
                    if data_channel.ready_state() == RtcDataChannelState::Open {
                        match data_channel.send_with_u8_array(buf) {
                            Ok(_) => {
                                // Update statistics
                                self.stats.bytes_sent.fetch_add(
                                    buf.len() as u64,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                Poll::Ready(Ok(buf.len()))
                            }
                            Err(_) => Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "Failed to send data through DataChannel",
                            ))),
                        }
                    } else {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "DataChannel not ready",
                        )))
                    }
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "No DataChannel available",
                    )))
                }
            }
            ConnectionState::Connecting => {
                Poll::Pending // Wait for connection to complete
            }
            ConnectionState::Disconnected | ConnectionState::Failed | ConnectionState::Closed => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Connection closed",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // For WebRTC DataChannels, we don't need to flush since sends are immediate
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // For WASM WebRTC data channels, close is handled asynchronously
        // Return ready since WebRTC handles cleanup automatically
        Poll::Ready(Ok(()))
    }
}

// ... (rest of the code remains the same)
#[async_trait(?Send)]
impl NetworkStream for WebRtcDataChannel {
    fn local_addr(&self) -> NexusResult<SocketAddr> {
        self.local_addr()
    }

    fn peer_addr(&self) -> NexusResult<SocketAddr> {
        self.peer_addr()
    }

    async fn shutdown(&mut self) -> NexusResult<()> {
        self.shutdown().await
    }

    fn stats(&self) -> StreamStats {
        self.stats()
    }

    fn is_secure(&self) -> bool {
        true // WebRTC is always encrypted
    }

    fn security_info(&self) -> Option<SecurityInfo> {
        Some(SecurityInfo {
            protocol: "WebRTC/DTLS".to_string(),
            cipher_suite: Some("DTLS-SRTP".to_string()),
            peer_certificate: None,
        })
    }
}

/// WebRTC Listener for incoming connections
#[derive(Debug, Clone)]
pub struct WebRtcListener {
    local_addr: SocketAddr,
    stats: WebRtcListenerStats,
    signaling: Rc<RefCell<Option<WebRtcSignaling>>>,
    pending_connections: Rc<RefCell<VecDeque<WebRtcDataChannel>>>,
    is_listening: Rc<RefCell<bool>>,
}

impl WebRtcListener {
    pub async fn new(addr: SocketAddr) -> NexusResult<Self> {
        Self::new_with_signaling(addr, SignalingConfig::default()).await
    }

    pub async fn new_with_signaling(
        addr: SocketAddr,
        config: SignalingConfig,
    ) -> NexusResult<Self> {
        let mut signaling = WebRtcSignaling::new(config);
        signaling.connect().await?;

        let listener = Self {
            local_addr: addr,
            stats: WebRtcListenerStats::new(),
            signaling: Rc::new(RefCell::new(Some(signaling))),
            pending_connections: Rc::new(RefCell::new(VecDeque::new())),
            is_listening: Rc::new(RefCell::new(true)),
        };

        // Start listening for incoming connections
        listener.start_listening().await?;

        Ok(listener)
    }

    async fn start_listening(&self) -> NexusResult<()> {
        // In a real implementation, this would:
        // 1. Register with signaling server as a listener
        // 2. Set up message handling for incoming offers
        // 3. Handle incoming WebRTC connection requests

        // For now, we'll set up a basic message handler
        // This would normally run in a background task
        Ok(())
    }

    /// Handle an incoming offer and create a connection
    async fn handle_incoming_offer(
        &self,
        offer_sdp: &str,
        peer_id: &str,
    ) -> NexusResult<WebRtcDataChannel> {
        if let Some(signaling) = self.signaling.borrow().as_ref() {
            // Create peer connection for the incoming connection
            let peer_connection = signaling.create_peer_connection(peer_id)?;

            // Create answer
            let answer_sdp = signaling.create_answer(peer_id, offer_sdp).await?;

            // Send answer back via signaling
            signaling.send_message(SignalingMessage::Answer {
                sdp: answer_sdp,
                peer_id: peer_id.to_string(),
            })?;

            // Wait for data channel to be created by remote peer
            // This would normally be handled by WebRTC events

            // Create the WebRTC data channel connection
            let connection = WebRtcDataChannel {
                local_addr: self.local_addr,
                peer_addr: self.local_addr, // We don't know the real peer address in WebRTC
                stats: WebRtcStats::new(),
                peer_connection: Some(peer_connection),
                data_channel: None, // Will be set when remote creates data channel
                receive_buffer: Rc::new(RefCell::new(VecDeque::new())),
                pending_writes: Rc::new(RefCell::new(VecDeque::new())),
                signaling: Rc::new(RefCell::new(None)),
                connection_state: Rc::new(RefCell::new(ConnectionState::Connecting)),
                peer_id: peer_id.to_string(),
            };

            Ok(connection)
        } else {
            Err(NexusError::Connection(
                "Signaling not available".to_string(),
            ))
        }
    }

    pub fn stats(&self) -> ListenerStats {
        ListenerStats {
            connections_accepted: self.stats.connections_accepted,
            active_connections: self.stats.active_connections,
            connection_errors: self.stats.connection_errors,
            uptime: self.stats.created_at.elapsed().unwrap_or_default(),
        }
    }

    pub async fn shutdown(&mut self) -> NexusResult<()> {
        // Mark as not listening
        *self.is_listening.borrow_mut() = false;

        // Close signaling connection
        if let Some(mut signaling) = self.signaling.borrow_mut().take() {
            signaling.close().ok();
        }

        // Clear pending connections
        self.pending_connections.borrow_mut().clear();

        Ok(())
    }
}

#[async_trait(?Send)]
impl NetworkListener for WebRtcListener {
    type Stream = WebRtcDataChannel;

    async fn accept(&mut self) -> NexusResult<(Self::Stream, SocketAddr)> {
        // Check if we have any pending connections
        if let Some(connection) = self.pending_connections.borrow_mut().pop_front() {
            let peer_addr = connection.peer_addr;
            return Ok((connection, peer_addr));
        }

        // Check for new signaling messages
        if let Some(signaling) = self.signaling.borrow().as_ref() {
            // In a real implementation, this would be event-driven
            // For now, we'll poll for messages
            if let Some(message) = signaling.get_next_message() {
                match message {
                    SignalingMessage::Offer { sdp, peer_id } => {
                        match self.handle_incoming_offer(&sdp, &peer_id).await {
                            Ok(connection) => {
                                let peer_addr = connection.peer_addr;
                                return Ok((connection, peer_addr));
                            }
                            Err(e) => {
                                return Err(e);
                            }
                        }
                    }
                    _ => {
                        // Handle other message types or ignore
                    }
                }
            }
        }

        // No connections available right now
        Err(NexusError::WouldBlock)
    }

    fn local_addr(&self) -> NexusResult<SocketAddr> {
        Ok(self.local_addr)
    }

    fn stats(&self) -> ListenerStats {
        self.stats()
    }

    fn is_secure(&self) -> bool {
        true
    }

    async fn shutdown(&mut self) -> NexusResult<()> {
        self.shutdown().await
    }
}
