//! Network listener abstractions

use async_trait::async_trait;
use std::net::SocketAddr;
use crate::error::NexusResult;
use super::NetworkStream;

/// Trait for network listeners that can accept incoming connections
/// 
/// This trait abstracts over different types of listeners such as TCP listeners,
/// QUIC endpoints, or WebRTC peer connection managers.
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait NetworkListener: 'static {
    /// The type of stream this listener produces
    type Stream: NetworkStream;
    
    /// Accept the next incoming connection
    /// 
    /// Returns a tuple of (stream, peer_address) for the new connection
    async fn accept(&mut self) -> NexusResult<(Self::Stream, SocketAddr)>;
    
    /// Get the local address this listener is bound to
    fn local_addr(&self) -> NexusResult<SocketAddr>;
    
    /// Get listener statistics
    fn stats(&self) -> ListenerStats;
    
    /// Check if this listener supports secure connections
    fn is_secure(&self) -> bool;
    
    /// Shutdown the listener gracefully
    async fn shutdown(&mut self) -> NexusResult<()>;
}

/// Statistics for network listeners
#[derive(Debug, Clone, Default)]
pub struct ListenerStats {
    /// Total connections accepted
    pub connections_accepted: u64,
    
    /// Currently active connections
    pub active_connections: u32,
    
    /// Total connection errors
    pub connection_errors: u64,
    
    /// Listener uptime
    pub uptime: std::time::Duration,
}

/// Configuration for network listeners
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// Bind address
    pub bind_addr: SocketAddr,
    
    /// Maximum pending connections (backlog)
    pub backlog: Option<u32>,
    
    /// Whether to enable SO_REUSEADDR
    pub reuse_addr: bool,
    
    /// Whether to enable SO_REUSEPORT (if supported)
    pub reuse_port: bool,
    
    /// Connection timeout
    pub accept_timeout: Option<std::time::Duration>,
    
    /// Security configuration
    pub security: Option<SecurityConfig>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            backlog: None,
            reuse_addr: true,
            reuse_port: false,
            accept_timeout: None,
            security: None,
        }
    }
}

/// Security configuration for listeners
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// TLS/DTLS certificate chain
    pub certificate_chain: Vec<u8>,
    
    /// Private key
    pub private_key: Vec<u8>,
    
    /// Supported cipher suites
    pub cipher_suites: Vec<String>,
    
    /// Client certificate requirement
    pub require_client_cert: bool,
}