//! Hole punch configuration module.
//!
//! This module provides the configuration structures for UDP hole punching.
//!
//! ## Example
//!
//! ```rust,no_run
//! use citadel_wire::udp_traversal::hole_punch_config::HolePunchConfig;
//! use citadel_wire::nat_identification::NatType;
//! use citadel_wire::error::FirewallError;
//! use citadel_io::tokio::net::UdpSocket;
//! use std::net::SocketAddr;
//!
//! async fn example() -> Result<(), FirewallError> {
//!     let socket = UdpSocket::bind("0.0.0.0:0").await?;
//!     let target_addr = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
//!     let peer_nat = NatType::identify(None).await?;
//!     let config = HolePunchConfig::new(&peer_nat, &[target_addr], vec![socket]);
//!     Ok(())
//! }
//! ```
//!
//! UDP Hole Punching Configuration
//!
//! This module provides configuration structures and utilities for UDP hole punching,
//! a NAT traversal technique that enables peer-to-peer connections between nodes
//! behind different NATs. It handles address prediction and socket preparation.
//!
//! # Features
//!
//! - NAT-aware address band configuration
//! - Port prediction for different NAT types
//! - Socket preparation for traversal
//! - IPv4 and IPv6 support
//! - Localhost testing capabilities
//! - Iterator-based address generation
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::udp_traversal::hole_punch_config::HolePunchConfig;
//! use citadel_wire::nat_identification::NatType;
//! use citadel_io::tokio::net::UdpSocket;
//! use std::net::SocketAddr;
//!
//! async fn setup_hole_punch() -> Result<(), anyhow::Error> {
//!     let peer_nat = NatType::identify(None).await?;
//!     let peer_addr = "192.168.1.2:8080".parse()?;
//!     let socket = UdpSocket::bind("0.0.0.0:0").await?;
//!     
//!     let config = HolePunchConfig::new(
//!         &peer_nat,
//!         &[peer_addr],
//!         vec![socket]
//!     );
//!     
//!     for addrs in config {
//!         // Try connecting to predicted addresses
//!         println!("Trying addresses: {addrs:?}");
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//!
//! - Address prediction depends on NAT type
//! - Multiple sockets may be required
//! - Port ranges are NAT-behavior specific
//! - Local sockets must be pre-bound
//! - IPv6 requires system configuration
//!
//! # Related Components
//!
//! - [`crate::nat_identification`] - NAT behavior analysis
//! - [`crate::udp_traversal::udp_hole_puncher`] - Hole punching implementation
//! - [`crate::standard::socket_helpers`] - Socket utilities
//! - [`crate::standard::upnp_handler`] - Alternative NAT traversal
//!

use crate::nat_identification::NatType;
use citadel_io::tokio::net::UdpSocket;
use itertools::Itertools;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug)]
pub struct HolePunchConfig {
    /// The IP addresses that must be connected to based on NAT traversal
    pub bands: Vec<Vec<AddrBand>>,
    // sockets bound to ports specially prepared for NAT traversal
    pub(crate) locally_bound_sockets: Option<Vec<UdpSocket>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct AddrBand {
    pub(crate) necessary_ip: IpAddr,
    pub(crate) anticipated_ports: Vec<u16>,
}

impl IntoIterator for HolePunchConfig {
    type Item = Vec<SocketAddr>;
    type IntoIter = std::vec::IntoIter<Vec<SocketAddr>>;

    fn into_iter(mut self) -> Self::IntoIter {
        // Use a HashSet to enforce uniqueness
        let mut ret = vec![];

        for band_set in self.bands.drain(..) {
            let mut this_set = vec![];
            for mut band in band_set {
                for next in band.by_ref() {
                    this_set.push(next);
                }
            }

            ret.push(this_set);
        }

        ret.into_iter()
    }
}

impl Iterator for AddrBand {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.anticipated_ports
            .pop()
            .map(|port| SocketAddr::new(self.necessary_ip, port))
    }
}

impl HolePunchConfig {
    pub fn new(
        peer_nat: &NatType,
        peer_internal_addrs: &[SocketAddr],
        local_sockets: Vec<UdpSocket>,
    ) -> Self {
        assert_eq!(peer_internal_addrs.len(), local_sockets.len());
        let mut this = HolePunchConfig {
            bands: Vec::new(),
            locally_bound_sockets: Some(local_sockets),
        };

        for peer_internal_addr in peer_internal_addrs {
            let mut bands = if let Some(bands) = peer_nat.predict(peer_internal_addr) {
                bands
            } else if cfg!(feature = "localhost-testing") {
                log::info!(target: "citadel", "Will revert to localhost testing mode (not recommended for production use (peer addr: {:?}))", peer_internal_addr);
                get_localhost_bands(peer_internal_addr)
            } else {
                // the peer nat is untraversable. However, they may still be able to connect to this node.
                // As such, we will only listen:
                vec![AddrBand {
                    necessary_ip: peer_internal_addr.ip(),
                    anticipated_ports: vec![peer_internal_addr.port()],
                }]
            };

            // Sometimes, even on localhost testing, both NATs are predictable, therefore the second branch above
            // does not execute. This means that it entirely misses out on the localhost adjacent node.
            // Therefore, we need to add it here:
            bands.extend(get_localhost_bands(peer_internal_addr));

            let bands = bands.into_iter().unique().collect();
            this.bands.push(bands)
        }

        this
    }
}

fn get_localhost_bands(peer_internal_addr: &SocketAddr) -> Vec<AddrBand> {
    vec![
        AddrBand {
            necessary_ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            anticipated_ports: vec![peer_internal_addr.port()],
        },
        AddrBand {
            necessary_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            anticipated_ports: vec![peer_internal_addr.port()],
        },
    ]
}
