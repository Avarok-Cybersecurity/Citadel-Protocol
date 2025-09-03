//! WebSocket implementation for WASM

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::error::{NexusResult, NexusError};
use crate::traits::{NetworkStream, NetworkListener, StreamStats, SecurityInfo, ListenerStats};

/// WebSocket stream implementation
pub struct WebSocketStream {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    is_secure: bool,
    stats: WebSocketStats,
    #[cfg(target_family = "wasm")]
    websocket: Option<web_sys::WebSocket>,
    #[cfg(target_family = "wasm")]
    receive_buffer: std::collections::VecDeque<Vec<u8>>,
    #[cfg(target_family = "wasm")]
    pending_messages: std::rc::Rc<std::cell::RefCell<std::collections::VecDeque<Vec<u8>>>>,
}

// Debug implementation since we can't derive it with web_sys types
impl std::fmt::Debug for WebSocketStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketStream")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("is_secure", &self.is_secure)
            .field("stats", &self.stats)
            .finish()
    }
}

impl WebSocketStream {
    pub async fn connect(addr: SocketAddr) -> NexusResult<Self> {
        #[cfg(target_family = "wasm")]
        {
            use wasm_bindgen::prelude::*;
            use wasm_bindgen_futures::JsFuture;
            use web_sys::*;
            use std::rc::Rc;
            use std::cell::RefCell;
            use futures::channel::oneshot;
            
            let url = if addr.port() == 443 || addr.port() == 8443 {
                format!("wss://{}:{}", addr.ip(), addr.port())
            } else {
                format!("ws://{}:{}", addr.ip(), addr.port())
            };
            
            let ws = WebSocket::new(&url)
                .map_err(|e| NexusError::Connection(format!("Failed to create WebSocket: {:?}", e)))?;
            
            ws.set_binary_type(web_sys::BinaryType::Arraybuffer);
            
            let (tx, rx) = oneshot::channel();
            let tx = Rc::new(RefCell::new(Some(tx)));
            
            // Set up connection handler
            let onopen_callback = Closure::wrap(Box::new(move || {
                if let Some(sender) = tx.borrow_mut().take() {
                    let _ = sender.send(Ok(()));
                }
            }) as Box<dyn FnMut()>);
            ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
            onopen_callback.forget(); // Keep alive
            
            let (err_tx, err_rx) = oneshot::channel();
            let err_tx = Rc::new(RefCell::new(Some(err_tx)));
            
            // Set up error handler  
            let onerror_callback = Closure::wrap(Box::new(move |_error: web_sys::ErrorEvent| {
                if let Some(sender) = err_tx.borrow_mut().take() {
                    let _ = sender.send(Err(NexusError::Connection("WebSocket connection error".to_string())));
                }
            }) as Box<dyn FnMut(web_sys::ErrorEvent)>);
            ws.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
            onerror_callback.forget(); // Keep alive
            
            // Wait for connection to complete
            futures::select! {
                result = rx => {
                    match result {
                        Ok(Ok(())) => {
                            // Connection successful
                            let local_addr = addr; // Browser doesn't expose actual local address
                            
                            let pending_messages = std::rc::Rc::new(std::cell::RefCell::new(std::collections::VecDeque::new()));
                            let pending_clone = pending_messages.clone();
                            
                            // Set up message handler
                            let onmessage_callback = Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
                                if let Ok(array_buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                                    let uint8_array = js_sys::Uint8Array::new(&array_buffer);
                                    let mut data = vec![0; uint8_array.length() as usize];
                                    uint8_array.copy_to(&mut data);
                                    pending_clone.borrow_mut().push_back(data);
                                }
                            }) as Box<dyn FnMut(web_sys::MessageEvent)>);
                            ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
                            onmessage_callback.forget(); // Keep alive
                            
                            Ok(Self {
                                local_addr,
                                peer_addr: addr,
                                is_secure: url.starts_with("wss://"),
                                stats: WebSocketStats::new(),
                                websocket: Some(ws),
                                receive_buffer: std::collections::VecDeque::new(),
                                pending_messages,
                            })
                        },
                        Ok(Err(e)) => Err(e),
                        Err(_) => Err(NexusError::Connection("Connection cancelled".to_string())),
                    }
                },
                result = err_rx => {
                    match result {
                        Ok(Err(e)) => Err(e),
                        _ => Err(NexusError::Connection("Connection failed".to_string())),
                    }
                }
            }
        }
        
        #[cfg(not(target_family = "wasm"))]
        Err(NexusError::NotSupported("WebSocket connect only supported on WASM".to_string()))
    }

    pub fn local_addr(&self) -> NexusResult<SocketAddr> {
        Ok(self.local_addr)
    }

    pub fn peer_addr(&self) -> NexusResult<SocketAddr> {
        Ok(self.peer_addr)
    }

    pub fn is_secure(&self) -> bool {
        self.is_secure
    }

    pub fn stats(&self) -> StreamStats {
        StreamStats {
            bytes_sent: self.stats.bytes_sent,
            bytes_received: self.stats.bytes_received,
            duration: self.stats.created_at.elapsed(),
            rtt: None, // WebSocket doesn't expose RTT
        }
    }

    pub fn security_info(&self) -> Option<SecurityInfo> {
        if self.is_secure {
            Some(SecurityInfo {
                protocol: "WSS".to_string(),
                cipher_suite: None, // Not exposed by WebSocket API
                peer_certificate: None,
            })
        } else {
            None
        }
    }

    pub async fn shutdown(&mut self) -> NexusResult<()> {
        // TODO: Close WebSocket connection
        Ok(())
    }
}

impl AsyncRead for WebSocketStream {
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
            
            // Check for new messages from WebSocket
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
            "WebSocket only supported on WASM"
        )))
    }
}

impl AsyncWrite for WebSocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        #[cfg(target_family = "wasm")]
        {
            if let Some(ref ws) = self.websocket {
                match ws.ready_state() {
                    web_sys::WebSocket::OPEN => {
                        let uint8_array = js_sys::Uint8Array::new_with_length(buf.len() as u32);
                        uint8_array.copy_from(buf);
                        
                        match ws.send_with_array_buffer(&uint8_array.buffer()) {
                            Ok(_) => {
                                let this = self.get_mut();
                                this.stats.bytes_sent += buf.len() as u64;
                                Poll::Ready(Ok(buf.len()))
                            },
                            Err(_) => Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "Failed to send WebSocket message"
                            )))
                        }
                    },
                    web_sys::WebSocket::CONNECTING => Poll::Pending,
                    _ => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "WebSocket is not connected"
                    )))
                }
            } else {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "WebSocket is not initialized"
                )))
            }
        }
        
        #[cfg(not(target_family = "wasm"))]
        Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "WebSocket only supported on WASM"
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // WebSocket messages are sent immediately
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        #[cfg(target_family = "wasm")]
        {
            if let Some(ref ws) = self.websocket {
                let _ = ws.close();
                self.websocket = None;
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl NetworkStream for WebSocketStream {
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
        self.is_secure()
    }

    fn security_info(&self) -> Option<SecurityInfo> {
        self.security_info()
    }
}

/// WebSocket listener (server-side functionality is limited in browsers)
#[derive(Debug)]
pub struct WebSocketListener {
    local_addr: SocketAddr,
    stats: WebSocketListenerStats,
}

impl WebSocketListener {
    pub async fn new(_addr: SocketAddr) -> NexusResult<Self> {
        // Note: Browsers cannot create WebSocket servers
        // This is here for API compatibility but will always fail
        Err(NexusError::NotSupported("WebSocket servers not supported in browsers".to_string()))
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

    pub fn is_secure(&self) -> bool {
        true // Assume WSS in browser context
    }

    pub async fn shutdown(&mut self) -> NexusResult<()> {
        Ok(())
    }
}

#[async_trait]
impl NetworkListener for WebSocketListener {
    type Stream = WebSocketStream;

    async fn accept(&mut self) -> NexusResult<(Self::Stream, SocketAddr)> {
        Err(NexusError::NotSupported("WebSocket servers not supported in browsers".to_string()))
    }

    fn local_addr(&self) -> NexusResult<SocketAddr> {
        self.local_addr()
    }

    fn stats(&self) -> ListenerStats {
        self.stats()
    }

    fn is_secure(&self) -> bool {
        self.is_secure()
    }

    async fn shutdown(&mut self) -> NexusResult<()> {
        self.shutdown().await
    }
}

// Internal stats structures
#[derive(Debug)]
struct WebSocketStats {
    bytes_sent: u64,
    bytes_received: u64,
    created_at: std::time::Instant,
}

impl WebSocketStats {
    fn new() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            created_at: std::time::Instant::now(),
        }
    }
}

#[derive(Debug)]
struct WebSocketListenerStats {
    connections_accepted: u64,
    active_connections: u32,
    connection_errors: u64,
    created_at: std::time::Instant,
}

impl WebSocketListenerStats {
    fn new() -> Self {
        Self {
            connections_accepted: 0,
            active_connections: 0,
            connection_errors: 0,
            created_at: std::time::Instant::now(),
        }
    }
}