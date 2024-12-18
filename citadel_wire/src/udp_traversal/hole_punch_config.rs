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
