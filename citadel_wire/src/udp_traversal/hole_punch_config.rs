#![cfg_attr(feature = "localhost-testing-loopback-only", allow(unreachable_code))]

use crate::nat_identification::NatType;
use citadel_io::tokio::net::UdpSocket;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug)]
pub struct HolePunchConfig {
    /// The IP addresses that must be connected to based on NAT traversal
    pub bands: Vec<AddrBand>,
    // sockets bound to ports specially prepared for NAT traversal
    pub(crate) locally_bound_sockets: Option<Vec<UdpSocket>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct AddrBand {
    pub(crate) necessary_ip: IpAddr,
    pub(crate) anticipated_ports: Vec<u16>,
}

impl IntoIterator for HolePunchConfig {
    type Item = SocketAddr;
    type IntoIter = std::collections::hash_set::IntoIter<SocketAddr>;

    fn into_iter(mut self) -> Self::IntoIter {
        // Use a HashSet to enforce uniqueness
        let mut ret = HashSet::new();

        for mut band in self.bands.drain(..) {
            for next in band.by_ref() {
                if next.ip() == IpAddr::from([0, 0, 0, 0]) {
                    // we never want to send to 0.0.0.0 addrs, only loopbacks
                    ret.insert(SocketAddr::new(IpAddr::from([127, 0, 0, 1]), next.port()));
                } else {
                    ret.insert(next);
                }
            }
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
        peer_internal_addr: &SocketAddr,
        local_socket: UdpSocket,
    ) -> Self {
        let mut this = if let Some(bands) = peer_nat.predict(peer_internal_addr) {
            Self {
                bands,
                locally_bound_sockets: Some(vec![local_socket]),
            }
        } else if cfg!(feature = "localhost-testing") {
            log::info!(target: "citadel", "Will revert to localhost testing mode (not recommended for production use (peer addr: {:?}))", peer_internal_addr);
            Self {
                bands: get_localhost_bands(peer_internal_addr),
                locally_bound_sockets: Some(vec![local_socket]),
            }
        } else {
            // the peer nat is untraversable. However, they may still be able to connect to this node.
            // As such, we will only listen:
            Self {
                bands: vec![AddrBand {
                    necessary_ip: peer_internal_addr.ip(),
                    anticipated_ports: vec![peer_internal_addr.port()],
                }],
                locally_bound_sockets: Some(vec![local_socket]),
            }
        };

        // Sometimes, even on localhost testing, both NATs are predictable, therefore the second branch above
        // does not execute. This means that it entirely misses out on the localhost adjacent node.
        // Therefore, we need to add it here:
        this.bands.extend(get_localhost_bands(peer_internal_addr));

        this
    }
}

fn get_localhost_bands(peer_internal_addr: &SocketAddr) -> Vec<AddrBand> {
    vec![AddrBand {
        necessary_ip: IpAddr::from([127, 0, 0, 1]),
        anticipated_ports: vec![peer_internal_addr.port()],
    }]
}
