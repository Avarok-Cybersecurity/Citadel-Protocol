//! Secure transport abstractions

use async_trait::async_trait;
use std::net::SocketAddr;
use crate::error::NexusResult;
use super::{NetworkStream, NetworkListener};

/// Trait for secure stream connections (TLS, DTLS, etc.)
#[async_trait] 
pub trait SecureStream: NetworkStream {
    /// Get the negotiated TLS/DTLS version
    fn protocol_version(&self) -> Option<String>;
    
    /// Get the negotiated cipher suite
    fn cipher_suite(&self) -> Option<String>;
    
    /// Get peer certificate chain (if available)
    fn peer_certificates(&self) -> Option<Vec<Vec<u8>>>;
    
    /// Verify peer certificate against expected identity
    fn verify_peer(&self, expected_identity: &str) -> NexusResult<bool>;
    
    /// Renegotiate the secure connection (if supported)
    async fn renegotiate(&mut self) -> NexusResult<()>;
}

/// Trait for secure listeners
#[async_trait]
pub trait SecureListener: NetworkListener {
    /// The type of secure stream this listener produces
    type SecureStream: SecureStream;
    
    /// Accept the next secure connection
    async fn accept_secure(&mut self) -> NexusResult<(Self::SecureStream, SocketAddr)>;
    
    /// Get the server certificate being used
    fn server_certificate(&self) -> Option<Vec<u8>>;
    
    /// Update the server certificate (if supported)
    async fn update_certificate(&mut self, cert_chain: Vec<u8>, private_key: Vec<u8>) -> NexusResult<()>;
}

/// TLS/DTLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Certificate chain (PEM format)
    pub certificate_chain: Vec<u8>,
    
    /// Private key (PEM format)  
    pub private_key: Vec<u8>,
    
    /// CA certificates for client verification
    pub ca_certificates: Option<Vec<u8>>,
    
    /// Supported protocol versions
    pub protocol_versions: Vec<TlsVersion>,
    
    /// Supported cipher suites  
    pub cipher_suites: Vec<String>,
    
    /// Require client certificate
    pub require_client_cert: bool,
    
    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
    
    /// Server name indication (for client connections)
    pub server_name: Option<String>,
}

/// TLS protocol versions
#[derive(Debug, Clone, PartialEq)]
pub enum TlsVersion {
    TLS1_0,
    TLS1_1, 
    TLS1_2,
    TLS1_3,
    DTLS1_0,
    DTLS1_2,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            certificate_chain: Vec::new(),
            private_key: Vec::new(),
            ca_certificates: None,
            protocol_versions: vec![TlsVersion::TLS1_2, TlsVersion::TLS1_3],
            cipher_suites: Vec::new(),
            require_client_cert: false,
            alpn_protocols: Vec::new(),
            server_name: None,
        }
    }
}

/// QUIC-specific configuration
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Base TLS configuration
    pub tls: TlsConfig,
    
    /// Maximum idle timeout
    pub max_idle_timeout: std::time::Duration,
    
    /// Initial maximum data
    pub initial_max_data: u64,
    
    /// Initial maximum stream data (bidirectional)
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    
    /// Initial maximum stream data (unidirectional)  
    pub initial_max_stream_data_uni: u64,
    
    /// Maximum concurrent bidirectional streams
    pub max_concurrent_bidi_streams: u32,
    
    /// Maximum concurrent unidirectional streams
    pub max_concurrent_uni_streams: u32,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            tls: TlsConfig::default(),
            max_idle_timeout: std::time::Duration::from_secs(30),
            initial_max_data: 10_000_000, // 10 MB
            initial_max_stream_data_bidi_local: 1_000_000, // 1 MB
            initial_max_stream_data_bidi_remote: 1_000_000, // 1 MB
            initial_max_stream_data_uni: 1_000_000, // 1 MB
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
        }
    }
}

/// Trait for QUIC endpoint operations
#[async_trait]
pub trait QuicEndpoint: Send + Sync + 'static {
    /// The stream type for QUIC connections
    type Stream: SecureStream;
    
    /// Connect to a QUIC server
    async fn connect(&self, addr: SocketAddr, server_name: &str) -> NexusResult<Self::Stream>;
    
    /// Accept incoming QUIC connections (server mode)
    async fn accept(&mut self) -> NexusResult<(Self::Stream, SocketAddr)>;
    
    /// Get local address
    fn local_addr(&self) -> NexusResult<SocketAddr>;
    
    /// Close the endpoint
    async fn close(&mut self) -> NexusResult<()>;
}