//! WebAssembly I/O provider implementation

use async_trait::async_trait;
use std::net::SocketAddr;

use super::nat::WasmNatTraversal;
use super::{WebRtcDataChannel, WebRtcListener, WebSocketStream};
use crate::error::{NexusError, NexusResult};
use crate::traits::CitadelIOInterface;
use crate::traits::DatagramSocket;
use crate::unified::{UnifiedNetworkListener, UnifiedNetworkStream};

/// WebAssembly implementation of the CitadelIOInterface
///
/// This provider uses WebRTC DataChannels for reliable streams and WebSockets
/// as fallback, with browser-based NAT traversal capabilities.
#[derive(Debug, Clone)]
pub struct WasmIOProvider {
    nat_traversal: WasmNatTraversal,
}

impl WasmIOProvider {
    /// Create a new WASM I/O provider
    pub async fn new() -> NexusResult<Self> {
        let nat_traversal = WasmNatTraversal::new().await?;

        Ok(Self { nat_traversal })
    }
}

#[async_trait(?Send)]
impl CitadelIOInterface for WasmIOProvider {
    type TcpListener = UnifiedNetworkListener;
    type TcpStream = UnifiedNetworkStream;
    type UdpSocket = WasmUdpSocket;
    type NatTraversal = WasmNatTraversal;

    async fn new() -> NexusResult<Self>
    where
        Self: Sized,
    {
        let nat_traversal = WasmNatTraversal::new().await?;

        Ok(Self { nat_traversal })
    }

    async fn bind_tcp(&self, addr: SocketAddr) -> NexusResult<Self::TcpListener> {
        // In WASM, we can't directly bind to TCP ports
        // Instead, we create a WebRTC listener that can accept incoming DataChannels
        let listener = WebRtcListener::new(addr).await?;
        Ok(UnifiedNetworkListener::WebRtc(listener))
    }

    async fn connect_tcp(&self, addr: SocketAddr) -> NexusResult<Self::TcpStream> {
        // Try WebRTC first, fallback to WebSocket
        match WebRtcDataChannel::connect(addr).await {
            Ok(channel) => Ok(UnifiedNetworkStream::WebRtc(channel)),
            Err(_) => {
                // Fallback to WebSocket
                let stream = WebSocketStream::connect(addr).await?;
                Ok(UnifiedNetworkStream::WebSocket(stream))
            }
        }
    }

    async fn bind_udp(&self, addr: SocketAddr) -> NexusResult<Self::UdpSocket> {
        // In WASM, UDP is simulated using WebRTC unreliable DataChannels
        WasmUdpSocket::bind(addr).await
    }

    fn nat_traversal(&self) -> &Self::NatTraversal {
        &self.nat_traversal
    }

    async fn get_local_ip_addrs(&self) -> NexusResult<Vec<std::net::IpAddr>> {
        // In WASM, we can't directly access local IP information
        // We'll have to use WebRTC to discover it, but for now return empty
        Ok(vec![])
    }
}

/// WASM UDP socket implementation using WebRTC unreliable DataChannels
pub struct WasmUdpSocket {
    local_addr: SocketAddr,
    #[cfg(target_family = "wasm")]
    peer_connection: Option<web_sys::RtcPeerConnection>,
    #[cfg(target_family = "wasm")]
    data_channel: Option<web_sys::RtcDataChannel>,
    #[cfg(target_family = "wasm")]
    pending_messages:
        std::rc::Rc<std::cell::RefCell<std::collections::VecDeque<(Vec<u8>, SocketAddr)>>>,
    #[cfg(target_family = "wasm")]
    recv_waker: std::rc::Rc<std::cell::RefCell<Option<std::task::Waker>>>,
    #[cfg(target_family = "wasm")]
    connected_peer: std::rc::Rc<std::cell::RefCell<Option<SocketAddr>>>,
    #[cfg(target_family = "wasm")]
    _onmessage_callback: Option<wasm_bindgen::closure::Closure<dyn FnMut(web_sys::MessageEvent)>>,
}

// Manual Debug implementation since Closure doesn't implement Debug
impl std::fmt::Debug for WasmUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmUdpSocket")
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

impl Drop for WasmUdpSocket {
    fn drop(&mut self) {
        #[cfg(target_family = "wasm")]
        {
            if let Some(ref pc) = self.peer_connection {
                pc.close();
            }
        }
    }
}

impl WasmUdpSocket {
    pub async fn bind(addr: SocketAddr) -> NexusResult<Self> {
        #[cfg(target_family = "wasm")]
        {
            use wasm_bindgen::prelude::*;
            use wasm_bindgen::{closure::Closure, JsCast};
            use web_sys::*;

            // Create WebRTC peer connection for unreliable transport
            let config = RtcConfiguration::new();
            let ice_servers = js_sys::Array::new();

            // Add STUN servers
            let stun_server = RtcIceServer::new();
            stun_server.set_urls(&JsValue::from_str("stun:stun.l.google.com:19302"));
            ice_servers.push(&stun_server);
            config.set_ice_servers(&ice_servers);

            let peer_connection =
                RtcPeerConnection::new_with_configuration(&config).map_err(|e| {
                    NexusError::Connection(format!("Failed to create UDP peer connection: {:?}", e))
                })?;

            // Create unreliable, unordered data channel for UDP-like behavior
            let data_channel_config = RtcDataChannelInit::new();
            data_channel_config.set_ordered(false);
            data_channel_config.set_max_retransmits(0); // No retransmits for fast transmissions like UDP

            let data_channel = peer_connection
                .create_data_channel_with_data_channel_dict("citadel-udp", &data_channel_config);

            let pending_messages =
                std::rc::Rc::new(std::cell::RefCell::new(std::collections::VecDeque::new()));
            let recv_waker: std::rc::Rc<std::cell::RefCell<Option<std::task::Waker>>> =
                std::rc::Rc::new(std::cell::RefCell::new(None));
            let connected_peer: std::rc::Rc<std::cell::RefCell<Option<SocketAddr>>> =
                std::rc::Rc::new(std::cell::RefCell::new(None));

            // Set up event handler for incoming messages
            let pending_messages_clone = pending_messages.clone();
            let recv_waker_clone = recv_waker.clone();
            let connected_peer_clone = connected_peer.clone();
            let onmessage_callback = Closure::wrap(Box::new(move |evt: web_sys::MessageEvent| {
                if let Ok(array_buffer) = evt.data().dyn_into::<js_sys::ArrayBuffer>() {
                    let uint8_array = js_sys::Uint8Array::new(&array_buffer);
                    let mut data = vec![0u8; uint8_array.length() as usize];
                    uint8_array.copy_to(&mut data);

                    // Use connected peer address if available, otherwise use a default
                    let peer_addr = connected_peer_clone
                        .borrow()
                        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

                    pending_messages_clone
                        .borrow_mut()
                        .push_back((data, peer_addr));

                    // Wake any task waiting on recv_from
                    if let Some(waker) = recv_waker_clone.borrow_mut().take() {
                        waker.wake();
                    }
                }
            }) as Box<dyn FnMut(_)>);

            data_channel.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));

            Ok(Self {
                local_addr: addr,
                peer_connection: Some(peer_connection),
                data_channel: Some(data_channel),
                pending_messages,
                recv_waker,
                connected_peer,
                _onmessage_callback: Some(onmessage_callback),
            })
        }

        #[cfg(not(target_family = "wasm"))]
        Ok(Self { local_addr: addr })
    }
}

#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
impl DatagramSocket for WasmUdpSocket {
    async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> NexusResult<usize> {
        #[cfg(target_family = "wasm")]
        {
            if let Some(ref data_channel) = self.data_channel {
                match data_channel.ready_state() {
                    web_sys::RtcDataChannelState::Open => {
                        let uint8_array = js_sys::Uint8Array::new_with_length(buf.len() as u32);
                        uint8_array.copy_from(buf);

                        match data_channel.send_with_array_buffer(&uint8_array.buffer()) {
                            Ok(_) => Ok(buf.len()),
                            Err(_) => Err(NexusError::Connection(
                                "Failed to send UDP message".to_string(),
                            )),
                        }
                    }
                    _ => Err(NexusError::Connection("DataChannel not ready".to_string())),
                }
            } else {
                Err(NexusError::Connection(
                    "DataChannel not initialized".to_string(),
                ))
            }
        }

        #[cfg(not(target_family = "wasm"))]
        Err(NexusError::NotSupported(
            "UDP send_to only supported on WASM".to_string(),
        ))
    }

    async fn recv_from(&self, buf: &mut [u8]) -> NexusResult<(usize, SocketAddr)> {
        #[cfg(target_family = "wasm")]
        {
            use std::future::poll_fn;
            use std::task::Poll;

            poll_fn(|cx| {
                // Try to get a message from the queue
                if let Some((data, addr)) = self.pending_messages.borrow_mut().pop_front() {
                    let to_copy = std::cmp::min(data.len(), buf.len());
                    buf[..to_copy].copy_from_slice(&data[..to_copy]);
                    return Poll::Ready(Ok((to_copy, addr)));
                }

                // No data available - register waker and return pending
                *self.recv_waker.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            })
            .await
        }

        #[cfg(not(target_family = "wasm"))]
        Err(NexusError::NotSupported(
            "UDP recv_from only supported on WASM".to_string(),
        ))
    }

    fn local_addr(&self) -> NexusResult<SocketAddr> {
        Ok(self.local_addr)
    }

    async fn connect(&self, addr: SocketAddr) -> NexusResult<()> {
        #[cfg(target_family = "wasm")]
        {
            // Store the connected peer address so incoming messages use it
            *self.connected_peer.borrow_mut() = Some(addr);
            log::debug!("UDP socket connected to {}", addr);
            Ok(())
        }

        #[cfg(not(target_family = "wasm"))]
        Err(NexusError::NotSupported(
            "UDP connect only supported on WASM".to_string(),
        ))
    }

    async fn send(&self, buf: &[u8]) -> NexusResult<usize> {
        #[cfg(target_family = "wasm")]
        {
            // Use the connected address (for connected UDP sockets)
            self.send_to(buf, self.local_addr).await
        }

        #[cfg(not(target_family = "wasm"))]
        Err(NexusError::NotSupported(
            "UDP send only supported on WASM".to_string(),
        ))
    }

    async fn recv(&self, buf: &mut [u8]) -> NexusResult<usize> {
        #[cfg(target_family = "wasm")]
        {
            let (bytes_read, _addr) = self.recv_from(buf).await?;
            Ok(bytes_read)
        }

        #[cfg(not(target_family = "wasm"))]
        Err(NexusError::NotSupported(
            "UDP recv only supported on WASM".to_string(),
        ))
    }

    fn stats(&self) -> crate::traits::DatagramStats {
        crate::traits::DatagramStats::default()
    }

    fn supports_multicast(&self) -> bool {
        false
    }

    async fn join_multicast(&self, _multicast_addr: SocketAddr) -> NexusResult<()> {
        Err(NexusError::NotSupported("Multicast in WASM".to_string()))
    }

    async fn leave_multicast(&self, _multicast_addr: SocketAddr) -> NexusResult<()> {
        Err(NexusError::NotSupported("Multicast in WASM".to_string()))
    }
}
