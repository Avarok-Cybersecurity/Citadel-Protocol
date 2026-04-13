//! NAT traversal abstractions

use super::DatagramSocket;
use crate::error::NexusResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// Trait for NAT traversal operations
///
/// This trait abstracts NAT detection, hole punching, and traversal strategies
/// across different platforms.
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait NatTraversal: Send + Sync + 'static {
    /// Identify the NAT type using STUN servers
    async fn identify_nat_type(&self, stun_servers: Vec<String>) -> NexusResult<NatType>;

    /// Perform UDP hole punching between two peers
    async fn punch_hole(
        &self,
        local_socket: &dyn DatagramSocket,
        peer_config: HolePunchConfig,
    ) -> NexusResult<HolePunchedSocket>;

    /// Get external IP address via STUN
    async fn get_external_ip(&self, stun_server: &str) -> NexusResult<IpAddr>;

    /// Test connectivity to a peer
    async fn test_connectivity(&self, peer_addr: SocketAddr) -> NexusResult<ConnectivityResult>;

    /// Get recommended traversal strategy for this NAT type
    fn get_traversal_strategy(&self, nat_type: &NatType) -> TraversalStrategy;
}

/// Types of NAT behavior detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NatType {
    /// No NAT - direct internet connection
    None,

    /// Full cone NAT - most permissive
    FullCone {
        external_ip: IpAddr,
        port_mapping: PortMapping,
    },

    /// Restricted cone NAT
    RestrictedCone {
        external_ip: IpAddr,
        port_mapping: PortMapping,
    },

    /// Port restricted cone NAT
    PortRestrictedCone {
        external_ip: IpAddr,
        port_mapping: PortMapping,
    },

    /// Symmetric NAT - most restrictive
    Symmetric {
        external_ips: Vec<IpAddr>,
        port_mapping: PortMapping,
    },

    /// Unknown/unidentifiable NAT behavior
    Unknown,

    /// Detection failed
    DetectionFailed(String),
}

/// Port mapping behavior for NAT
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortMapping {
    /// Port numbers are preserved (internal:external same)
    Preserved,

    /// Port is translated by a fixed offset
    FixedOffset(i32),

    /// Port translation follows a predictable pattern
    Predictable {
        pattern: MappingPattern,
        last_port: u16,
    },

    /// Port translation is random/unpredictable
    Random,
}

/// Patterns for predictable port mapping
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MappingPattern {
    /// Sequential increment
    Sequential,
    /// Fixed step increment
    FixedStep(u16),
    /// Custom pattern
    Custom(Vec<i32>),
}

/// Configuration for hole punching operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolePunchConfig {
    /// Peer's public address information
    pub peer_public_addr: SocketAddr,

    /// Peer's private address (if known)
    pub peer_private_addr: Option<SocketAddr>,

    /// Peer's NAT type
    pub peer_nat_type: NatType,

    /// Hole punching strategy to use
    pub strategy: TraversalStrategy,

    /// Timeout for hole punching attempt
    pub timeout: std::time::Duration,

    /// Number of retry attempts
    pub max_retries: u32,

    /// Authentication token for peer verification
    pub auth_token: Option<Vec<u8>>,
}

/// Result of a successful hole punch operation
pub struct HolePunchedSocket {
    /// The socket with established connection
    pub socket: Box<dyn DatagramSocket>,

    /// Confirmed peer address
    pub peer_addr: SocketAddr,

    /// Statistics from the hole punching process
    pub stats: HolePunchStats,
}

/// Statistics from hole punching attempts
#[derive(Debug, Clone, Default)]
pub struct HolePunchStats {
    /// Number of attempts made
    pub attempts: u32,

    /// Time taken to establish connection
    pub duration: std::time::Duration,

    /// Final strategy that succeeded
    pub successful_strategy: Option<TraversalStrategy>,

    /// Bytes exchanged during process
    pub bytes_exchanged: u64,
}

/// Different strategies for NAT traversal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TraversalStrategy {
    /// Direct connection (no NAT)
    Direct,

    /// Simple UDP hole punching
    SimpleHolePunch,

    /// Sequential hole punching (try multiple ports)
    SequentialHolePunch { start_port: u16, port_range: u16 },

    /// Simultaneous open technique
    SimultaneousOpen,

    /// Port prediction based on NAT behavior
    PortPrediction { predicted_ports: Vec<u16> },

    /// Use TURN relay as fallback
    TurnRelay {
        relay_server: String,
        credentials: Option<TurnCredentials>,
    },

    /// Multiple strategies in sequence
    Sequential(Vec<TraversalStrategy>),

    /// Multiple strategies in parallel
    Parallel(Vec<TraversalStrategy>),
}

/// TURN server credentials
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TurnCredentials {
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
}

/// Result of connectivity testing
#[derive(Debug, Clone)]
pub struct ConnectivityResult {
    /// Whether connection was successful
    pub success: bool,

    /// Round-trip time if successful
    pub rtt: Option<std::time::Duration>,

    /// Error message if failed
    pub error: Option<String>,

    /// Packet loss percentage
    pub packet_loss: Option<f32>,
}

/// Default STUN servers for NAT detection
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
];

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            peer_public_addr: "0.0.0.0:0".parse().unwrap(),
            peer_private_addr: None,
            peer_nat_type: NatType::Unknown,
            strategy: TraversalStrategy::SimpleHolePunch,
            timeout: std::time::Duration::from_secs(10),
            max_retries: 3,
            auth_token: None,
        }
    }
}
