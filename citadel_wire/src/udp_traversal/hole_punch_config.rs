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
    ) -> Result<Self, anyhow::Error> {
        let bands = peer_nat
            .predict(peer_internal_addr)
            .ok_or_else(|| anyhow::Error::msg("Peer NAT type is untraversable"))?;
        Ok(Self {
            bands,
            locally_bound_sockets: Some(vec![local_socket]),
        })
    }
}
