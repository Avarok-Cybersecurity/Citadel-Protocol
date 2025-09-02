//! NAT traversal implementation for standard targets

use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::error::{NexusResult, NexusError};
use crate::traits::{
    NatTraversal, NatType, HolePunchConfig, HolePunchedSocket, DatagramSocket, 
    TraversalStrategy, ConnectivityResult, HolePunchStats, DEFAULT_STUN_SERVERS
};
use super::StdUdpSocket;

/// Standard implementation of NAT traversal using existing citadel_wire functionality
#[derive(Debug)]
pub struct StdNatTraversal {
    // Cache the detected NAT type to avoid repeated detection
    cached_nat_type: citadel_io::Mutex<Option<NatType>>,
}

impl StdNatTraversal {
    pub async fn new() -> NexusResult<Self> {
        Ok(Self {
            cached_nat_type: citadel_io::Mutex::new(None),
        })
    }
}

impl Clone for StdNatTraversal {
    fn clone(&self) -> Self {
        Self {
            cached_nat_type: citadel_io::Mutex::new(None),
        }
    }
}

#[async_trait]
impl NatTraversal for StdNatTraversal {
    async fn identify_nat_type(&self, stun_servers: Vec<String>) -> NexusResult<NatType> {
        // Check cache first
        {
            let cache = self.cached_nat_type.lock();
            if let Some(cached) = &*cache {
                return Ok(cached.clone());
            }
        }

        let servers = if stun_servers.is_empty() {
            DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect()
        } else {
            stun_servers
        };

        // TODO: Use citadel_wire's NAT identification once dependencies are resolved
        // For now, return a default NAT type
        let converted_nat_type = NatType::RestrictedCone {
            external_ip: "0.0.0.0".parse().unwrap(),
            port_mapping: crate::traits::PortMapping::Random,
        };

        // Cache the result
        {
            let mut cache = self.cached_nat_type.lock();
            *cache = Some(converted_nat_type.clone());
        }

        Ok(converted_nat_type)
    }

    async fn punch_hole(
        &self,
        local_socket: &dyn DatagramSocket,
        config: HolePunchConfig,
    ) -> NexusResult<HolePunchedSocket> {
        let start_time = std::time::Instant::now();
        
        // TODO: Implement proper hole punching
        // For now, return a placeholder result
        let hole_punch_result = HolePunchResult {
            socket: StdUdpSocket::bind("0.0.0.0:0".parse().unwrap()).await?,
            attempts: 1,
            bytes_exchanged: 0,
        };

        let stats = HolePunchStats {
            attempts: hole_punch_result.attempts,
            duration: start_time.elapsed(),
            successful_strategy: Some(config.strategy.clone()),
            bytes_exchanged: hole_punch_result.bytes_exchanged,
        };

        Ok(HolePunchedSocket {
            socket: Box::new(hole_punch_result.socket),
            peer_addr: config.peer_public_addr,
            stats,
        })
    }

    async fn get_external_ip(&self, _stun_server: &str) -> NexusResult<IpAddr> {
        // TODO: Implement STUN query
        Ok("0.0.0.0".parse().unwrap())
    }

    async fn test_connectivity(&self, peer_addr: SocketAddr) -> NexusResult<ConnectivityResult> {
        let start_time = std::time::Instant::now();
        
        // Create a test socket
        let socket = StdUdpSocket::bind("0.0.0.0:0".parse().unwrap()).await?;
        
        // Send test packet
        let test_data = b"citadel_connectivity_test";
        let mut attempts = 0;
        let max_attempts = 3;
        
        while attempts < max_attempts {
            match socket.send_to(test_data, peer_addr).await {
                Ok(_) => {
                    // Try to receive response with timeout
                    let mut buf = [0u8; 1024];
                    let timeout = Duration::from_millis(1000);
                    
                    match citadel_io::tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
                        Ok(Ok((len, addr))) if addr == peer_addr && len >= test_data.len() => {
                            return Ok(ConnectivityResult {
                                success: true,
                                rtt: Some(start_time.elapsed()),
                                error: None,
                                packet_loss: Some(0.0),
                            });
                        }
                        Ok(Ok(_)) => {
                            // Got a response but from wrong peer or wrong data
                        }
                        Ok(Err(e)) => {
                            return Ok(ConnectivityResult {
                                success: false,
                                rtt: None,
                                error: Some(e.to_string()),
                                packet_loss: Some(100.0),
                            });
                        }
                        Err(_) => {
                            // Timeout
                        }
                    }
                }
                Err(e) => {
                    return Ok(ConnectivityResult {
                        success: false,
                        rtt: None,
                        error: Some(e.to_string()),
                        packet_loss: Some(100.0),
                    });
                }
            }
            
            attempts += 1;
            // Brief delay before retry
            citadel_io::tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(ConnectivityResult {
            success: false,
            rtt: None,
            error: Some("No response after 3 attempts".to_string()),
            packet_loss: Some(100.0),
        })
    }

    fn get_traversal_strategy(&self, nat_type: &NatType) -> TraversalStrategy {
        match nat_type {
            NatType::None => TraversalStrategy::Direct,
            NatType::FullCone { .. } => TraversalStrategy::SimpleHolePunch,
            NatType::RestrictedCone { .. } => TraversalStrategy::SimpleHolePunch,
            NatType::PortRestrictedCone { .. } => TraversalStrategy::SequentialHolePunch {
                start_port: 1024,
                port_range: 100,
            },
            NatType::Symmetric { .. } => TraversalStrategy::Parallel(vec![
                TraversalStrategy::PortPrediction { predicted_ports: vec![] },
                TraversalStrategy::SimultaneousOpen,
            ]),
            NatType::Unknown | NatType::DetectionFailed(_) => TraversalStrategy::Sequential(vec![
                TraversalStrategy::SimpleHolePunch,
                TraversalStrategy::SequentialHolePunch {
                    start_port: 1024,
                    port_range: 200,
                },
            ]),
        }
    }
}

// TODO: Implement proper hole punching once trait system is finalized
// For now, use a simplified approach

// TODO: Add helper functions for NAT type conversion once dependencies are resolved

// Result structure for hole punching
struct HolePunchResult {
    socket: StdUdpSocket,
    attempts: u32,
    bytes_exchanged: u64,
}

// Perform the actual hole punching
async fn perform_hole_punch(
    socket: &StdUdpSocket,
    config: &HolePunchConfig,
) -> NexusResult<HolePunchResult> {
    // Configure socket for NAT traversal
    socket.configure_for_nat_traversal()?;

    let local_addr = socket.local_addr()?;
    let mut attempts = 0;
    let mut bytes_exchanged = 0u64;

    // Try different strategies based on config
    match &config.strategy {
        TraversalStrategy::Direct => {
            // Just test direct connectivity
            socket.send_to(b"ping", config.peer_public_addr).await?;
            attempts = 1;
            bytes_exchanged = 4;
        }
        
        TraversalStrategy::SimpleHolePunch => {
            // Send packets to peer address to create NAT mapping
            for i in 0..config.max_retries {
                let message = format!("hole_punch_{}", i);
                socket.send_to(message.as_bytes(), config.peer_public_addr).await?;
                bytes_exchanged += message.len() as u64;
                attempts += 1;
                
                // Brief delay between attempts
                citadel_io::tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        
        TraversalStrategy::SequentialHolePunch { start_port, port_range } => {
            // Try different port combinations
            let base_addr = config.peer_public_addr.ip();
            for port_offset in 0..*port_range {
                let target_port = start_port.wrapping_add(port_offset);
                let target_addr = SocketAddr::new(base_addr, target_port);
                
                let message = format!("seq_hole_punch_{}", target_port);
                if let Ok(_) = socket.send_to(message.as_bytes(), target_addr).await {
                    bytes_exchanged += message.len() as u64;
                }
                attempts += 1;
                
                if attempts >= config.max_retries {
                    break;
                }
            }
        }
        
        _ => {
            // Fallback to simple hole punch for other strategies
            socket.send_to(b"hole_punch", config.peer_public_addr).await?;
            attempts = 1;
            bytes_exchanged = 10;
        }
    }

    // Create a new socket with the same configuration for the result
    let result_socket = StdUdpSocket::bind_for_nat_traversal(local_addr).await?;
    
    Ok(HolePunchResult {
        socket: result_socket,
        attempts,
        bytes_exchanged,
    })
}

// TODO: Implement STUN query functionality