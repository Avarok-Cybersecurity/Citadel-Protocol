#![cfg_attr(feature = "localhost-testing-loopback-only", allow(unreachable_code))]
use crate::nat_identification::NatType;
use citadel_io::UdpSocket;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug)]
pub struct HolePunchConfig {
    /// The IP address that must be connected to based on NAT traversal
    pub bands: Vec<AddrBand>,
    // sockets bound to ports specially prepared for NAT traversal
    pub(crate) locally_bound_sockets: Option<Vec<UdpSocket>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AddrBand {
    pub(crate) necessary_ip: IpAddr,
    pub(crate) anticipated_ports: Vec<u16>,
}

impl IntoIterator for HolePunchConfig {
    type Item = SocketAddr;
    type IntoIter = std::vec::IntoIter<SocketAddr>;

    fn into_iter(mut self) -> Self::IntoIter {
        let mut ret = vec![];

        for band in self.bands.iter_mut() {
            for next in band.by_ref() {
                ret.push(next);
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
        if let Some(bands) = peer_nat.predict(peer_internal_addr) {
            Self {
                bands,
                locally_bound_sockets: Some(vec![local_socket]),
            }
        } else if cfg!(feature = "localhost-testing") {
            log::info!(target: "citadel", "Will revert to localhost testing mode (not recommended for production use (peer addr: {:?}))", peer_internal_addr);
            Self {
                bands: vec![
                    AddrBand {
                        necessary_ip: IpAddr::from([127, 0, 0, 1]),
                        anticipated_ports: vec![peer_internal_addr.port()],
                    },
                    AddrBand {
                        necessary_ip: IpAddr::from([0, 0, 0, 0]),
                        anticipated_ports: vec![peer_internal_addr.port()],
                    },
                ],
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
        }
    }
}
