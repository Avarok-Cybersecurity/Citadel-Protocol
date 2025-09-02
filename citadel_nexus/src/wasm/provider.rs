//! WebAssembly I/O provider implementation

use async_trait::async_trait;
use std::net::SocketAddr;

use crate::error::{NexusResult, NexusError};
use crate::traits::{CitadelIOInterface, PlatformInfo, IpInfo};
use crate::unified::{UnifiedNetworkStream, UnifiedNetworkListener};
use super::{WebRtcDataChannel, WebRtcListener, WebSocketStream, WebSocketListener};
use super::nat::WasmNatTraversal;

/// WebAssembly implementation of the CitadelIOInterface
/// 
/// This provider uses WebRTC DataChannels for reliable streams and WebSockets
/// as fallback, with browser-based NAT traversal capabilities.
#[derive(Debug)]
pub struct WasmIOProvider {
    nat_traversal: WasmNatTraversal,
}

impl WasmIOProvider {
    /// Create a new WASM I/O provider
    pub async fn new() -> NexusResult<Self> {
        let nat_traversal = WasmNatTraversal::new().await?;
        
        Ok(Self {
            nat_traversal,
        })
    }
}

#[async_trait]
impl CitadelIOInterface for WasmIOProvider {
    type TcpListener = UnifiedNetworkListener;
    type TcpStream = UnifiedNetworkStream;
    type UdpSocket = WasmUdpSocket;
    type NatTraversal = WasmNatTraversal;

    async fn new() -> NexusResult<Self> {
        Self::new().await
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

    async fn get_local_ip_info(&self) -> NexusResult<IpInfo> {
        // In WASM, we can't directly access local IP information
        // We'll have to use WebRTC to discover it
        Ok(IpInfo {
            ipv4: None, // Will be discovered via WebRTC
            ipv6: None, // Not typically available in browsers
            behind_nat: Some(true), // Browsers are always behind NAT
        })
    }

    fn supports_ipv6(&self) -> bool {
        false // Generally not available in browsers
    }

    fn supports_quic(&self) -> bool {
        false // Not available in browsers yet
    }

    fn supports_tls(&self) -> bool {
        true // WebSockets can use WSS, WebRTC is always encrypted
    }

    fn platform_info(&self) -> PlatformInfo {
        PlatformInfo {
            name: "wasm",
            features: vec![
                "webrtc", "websocket", "browser-based-nat-traversal"
            ],
            max_connections: Some(256), // Browser connection limits
        }
    }
}

/// Placeholder UDP socket for WASM (using WebRTC unreliable DataChannels)
#[derive(Debug)]
pub struct WasmUdpSocket {
    // TODO: Implement using WebRTC unreliable DataChannels
    local_addr: SocketAddr,
}

impl WasmUdpSocket {
    pub async fn bind(addr: SocketAddr) -> NexusResult<Self> {
        Ok(Self {
            local_addr: addr,
        })
    }
}

#[async_trait]
impl crate::traits::DatagramSocket for WasmUdpSocket {
    async fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> NexusResult<usize> {
        Err(NexusError::NotSupported("UDP send_to in WASM".to_string()))
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> NexusResult<(usize, SocketAddr)> {
        Err(NexusError::NotSupported("UDP recv_from in WASM".to_string()))
    }

    fn local_addr(&self) -> NexusResult<SocketAddr> {
        Ok(self.local_addr)
    }

    async fn connect(&self, _addr: SocketAddr) -> NexusResult<()> {
        Err(NexusError::NotSupported("UDP connect in WASM".to_string()))
    }

    async fn send(&self, _buf: &[u8]) -> NexusResult<usize> {
        Err(NexusError::NotSupported("UDP send in WASM".to_string()))
    }

    async fn recv(&self, _buf: &mut [u8]) -> NexusResult<usize> {
        Err(NexusError::NotSupported("UDP recv in WASM".to_string()))
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