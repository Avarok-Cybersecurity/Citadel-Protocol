//! WebRTC DataChannel implementation for WASM

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::error::{NexusResult, NexusError};
use crate::traits::{NetworkStream, NetworkListener, StreamStats, SecurityInfo, ListenerStats};

/// WebRTC DataChannel implementation for reliable streams  
pub struct WebRtcDataChannel {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    stats: WebRtcStats,
    #[cfg(target_family = "wasm")]
    peer_connection: Option<web_sys::RtcPeerConnection>,
    #[cfg(target_family = "wasm")]
    data_channel: Option<web_sys::RtcDataChannel>,
    #[cfg(target_family = "wasm")]
    receive_buffer: std::collections::VecDeque<Vec<u8>>,
    #[cfg(target_family = "wasm")]
    pending_messages: std::rc::Rc<std::cell::RefCell<std::collections::VecDeque<Vec<u8>>>>,
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
        #[cfg(target_family = "wasm")]
        {
            use wasm_bindgen::prelude::*;
            use web_sys::*;
            use futures::channel::oneshot;
            use std::rc::Rc;
            use std::cell::RefCell;
            
            // Create peer connection configuration
            let mut config = RtcConfiguration::new();
            let ice_servers = js_sys::Array::new();
            
            // Add STUN servers for NAT traversal
            let stun_server = RtcIceServer::new();
            stun_server.set_urls(&JsValue::from_str("stun:stun.l.google.com:19302"));
            ice_servers.push(&stun_server);
            
            config.ice_servers(&ice_servers);
            
            // Create peer connection
            let peer_connection = RtcPeerConnection::new_with_configuration(&config)
                .map_err(|e| NexusError::Connection(format!("Failed to create peer connection: {:?}", e)))?;
            
            // Create data channel
            let mut data_channel_config = RtcDataChannelInit::new();
            data_channel_config.ordered(true); // Reliable, ordered delivery
            
            let data_channel = peer_connection.create_data_channel_with_data_channel_dict(\"citadel\", &data_channel_config);
            
            // Set up message handling for the data channel
            let pending_messages = std::rc::Rc::new(std::cell::RefCell::new(std::collections::VecDeque::new()));
            let pending_clone = pending_messages.clone();
            
            let onmessage_callback = Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
                if let Ok(array_buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                    let uint8_array = js_sys::Uint8Array::new(&array_buffer);
                    let mut data = vec![0; uint8_array.length() as usize];
                    uint8_array.copy_to(&mut data);
                    pending_clone.borrow_mut().push_back(data);
                }
            }) as Box<dyn FnMut(web_sys::MessageEvent)>);
            
            data_channel.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
            onmessage_callback.forget(); // Keep alive
            
            // Wait for data channel to open
            let (tx, rx) = oneshot::channel();
            let tx = Rc::new(RefCell::new(Some(tx)));
            
            let onopen_callback = Closure::wrap(Box::new(move || {
                if let Some(sender) = tx.borrow_mut().take() {
                    let _ = sender.send(Ok(()));
                }
            }) as Box<dyn FnMut()>);
            data_channel.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
            onopen_callback.forget(); // Keep alive
            
            // NOTE: In a real implementation, we would need to:
            // 1. Create offer/answer
            // 2. Exchange SDP via signaling server
            // 3. Handle ICE candidates
            // 4. Wait for connection to be established
            // For now, we'll create the structure but mark it as not fully connected
            
            let local_addr = addr; // Browser doesn't expose actual local address
            Ok(Self {
                local_addr,
                peer_addr: addr,
                stats: WebRtcStats::new(),
                peer_connection: Some(peer_connection),
                data_channel: Some(data_channel),
                receive_buffer: std::collections::VecDeque::new(),
                pending_messages,
            })
        }
        
        #[cfg(not(target_family = "wasm"))]
        Err(NexusError::NotSupported("WebRTC connect only supported on WASM".to_string()))
    }

    pub fn local_addr(&self) -> NexusResult<SocketAddr> {
        Ok(self.local_addr)
    }

    pub fn peer_addr(&self) -> NexusResult<SocketAddr> {
        Ok(self.peer_addr)
    }

    pub fn stats(&self) -> StreamStats {
        StreamStats {
            bytes_sent: self.stats.bytes_sent,
            bytes_received: self.stats.bytes_received,
            duration: self.stats.created_at.elapsed(),
            rtt: self.stats.rtt,
        }
    }

    pub async fn shutdown(&mut self) -> NexusResult<()> {
        // TODO: Close DataChannel
        Ok(())
    }
}

impl AsyncRead for WebRtcDataChannel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        #[cfg(target_family = "wasm")]
        {
            // First check our local buffer
            if let Some(data) = self.receive_buffer.pop_front() {
                let to_copy = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_copy]);
                
                // If we didn't consume all data, put the rest back
                if to_copy < data.len() {
                    self.receive_buffer.push_front(data[to_copy..].to_vec());
                }
                
                self.stats.bytes_received += to_copy as u64;
                return Poll::Ready(Ok(()));
            }
            
            // Check for new messages from DataChannel
            if let Some(pending_data) = self.pending_messages.borrow_mut().pop_front() {
                let to_copy = std::cmp::min(pending_data.len(), buf.remaining());
                buf.put_slice(&pending_data[..to_copy]);
                
                // If we didn't consume all data, store the rest
                if to_copy < pending_data.len() {
                    self.receive_buffer.push_back(pending_data[to_copy..].to_vec());
                }
                
                self.stats.bytes_received += to_copy as u64;
                return Poll::Ready(Ok(()));
            }
            
            // No data available, need to wait
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        
        #[cfg(not(target_family = "wasm"))]
        Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "WebRTC only supported on WASM"
        )))
    }
}

impl AsyncWrite for WebRtcDataChannel {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        #[cfg(target_family = "wasm")]
        {
            if let Some(ref data_channel) = self.data_channel {
                match data_channel.ready_state() {
                    web_sys::RtcDataChannelState::Open => {
                        let uint8_array = js_sys::Uint8Array::new_with_length(buf.len() as u32);
                        uint8_array.copy_from(buf);
                        
                        match data_channel.send_with_array_buffer(&uint8_array.buffer()) {
                            Ok(_) => {
                                let this = self.get_mut();
                                this.stats.bytes_sent += buf.len() as u64;
                                Poll::Ready(Ok(buf.len()))
                            },
                            Err(_) => Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "Failed to send DataChannel message"
                            )))
                        }
                    },
                    web_sys::RtcDataChannelState::Connecting => Poll::Pending,
                    _ => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "DataChannel is not connected"
                    )))
                }
            } else {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "DataChannel is not initialized"
                )))
            }
        }
        
        #[cfg(not(target_family = "wasm"))]
        Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "WebRTC only supported on WASM"
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // DataChannel messages are sent immediately
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        #[cfg(target_family = "wasm")]
        {
            if let Some(ref data_channel) = self.data_channel {
                data_channel.close();
                self.data_channel = None;
            }
            if let Some(ref peer_connection) = self.peer_connection {
                peer_connection.close();
                self.peer_connection = None;
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
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
            peer_certificate: None, // TODO: Extract from WebRTC
        })
    }
}

/// WebRTC listener for accepting incoming DataChannel connections
#[derive(Debug)]
pub struct WebRtcListener {
    local_addr: SocketAddr,
    stats: WebRtcListenerStats,
}

impl WebRtcListener {
    pub async fn new(addr: SocketAddr) -> NexusResult<Self> {
        // TODO: Set up WebRTC listener
        // This would involve:
        // 1. Setting up signaling channel
        // 2. Preparing for incoming connection offers
        // 3. Managing ICE servers
        
        Ok(Self {
            local_addr: addr,
            stats: WebRtcListenerStats::new(),
        })
    }

    pub fn local_addr(&self) -> NexusResult<SocketAddr> {
        Ok(self.local_addr)
    }

    pub fn stats(&self) -> ListenerStats {
        ListenerStats {
            connections_accepted: self.stats.connections_accepted,
            active_connections: self.stats.active_connections,
            connection_errors: self.stats.connection_errors,
            uptime: self.stats.created_at.elapsed(),
        }
    }

    pub async fn shutdown(&mut self) -> NexusResult<()> {
        // TODO: Close listener and cleanup resources
        Ok(())
    }
}

#[async_trait]
impl NetworkListener for WebRtcListener {
    type Stream = WebRtcDataChannel;

    async fn accept(&mut self) -> NexusResult<(Self::Stream, SocketAddr)> {
        // TODO: Accept incoming WebRTC connection
        // This would involve:
        // 1. Receiving connection offer via signaling
        // 2. Creating answer
        // 3. Handling ICE candidate exchange
        // 4. Waiting for DataChannel to be established
        
        Err(NexusError::NotSupported("WebRTC accept not yet implemented".to_string()))
    }

    fn local_addr(&self) -> NexusResult<SocketAddr> {
        self.local_addr()
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

// Internal stats structures
#[derive(Debug)]
struct WebRtcStats {
    bytes_sent: u64,
    bytes_received: u64,
    created_at: std::time::Instant,
    rtt: Option<std::time::Duration>,
}

impl WebRtcStats {
    fn new() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            created_at: std::time::Instant::now(),
            rtt: None,
        }
    }
}

#[derive(Debug)]
struct WebRtcListenerStats {
    connections_accepted: u64,
    active_connections: u32,
    connection_errors: u64,
    created_at: std::time::Instant,
}

impl WebRtcListenerStats {
    fn new() -> Self {
        Self {
            connections_accepted: 0,
            active_connections: 0,
            connection_errors: 0,
            created_at: std::time::Instant::now(),
        }
    }
}