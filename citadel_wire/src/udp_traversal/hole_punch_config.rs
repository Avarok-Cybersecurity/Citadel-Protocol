#![cfg_attr(feature = "localhost-testing-loopback-only", allow(unreachable_code))]
use crate::nat_identification::NatType;
use async_ip::IpAddressInfo;
use citadel_io::UdpSocket;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug)]
pub struct HolePunchConfig {
    /// The IP address that must be connected to based on NAT traversal
    pub bands: Vec<AddrBand>,
    // sockets bound to ports specially prepared for NAT traversal
    pub(crate) locally_bound_sockets: Option<Vec<UdpSocket>>,
}

const SPREAD: u16 = 6;

impl HolePunchConfig {
    /// The expectation is that both `local_nat_info` and `peer_nat_info`
    /// were both *recently* obtained, since the port information may no longer
    /// be relevant in a busy NAT
    ///
    /// Will return None if hole punching is determined not to be possible (TURN required)
    ///
    /// `initial_local_socket` is necessary since the peer must also know the declared internal port.
    /// Once the initial local socket is created, it is expect that its bind port is sent to the peer,
    /// where that value will be passed to this function as `peer_declared_internal_port1
    /// SO_REUSE does not need to be on for `initial_local_socket`
    pub fn new(
        local_nat_info: &NatType,
        peer_nat_info: &NatType,
        first_local_socket: UdpSocket,
        peer_declared_internal_port: u16,
    ) -> Result<Self, anyhow::Error> {
        // if this is not localhost testing, always check
        // we do not check when doing localhost-testing since we don't want
        // a runner behind an unpredictable NAT to error out
        #[cfg(not(feature = "localhost-testing"))]
        {
            if !local_nat_info.stun_compatible(peer_nat_info) {
                return Err(anyhow::Error::msg(
                    "This cannot be called if STUN is not compatible",
                ));
            }
        }

        // below is only needed if the peer is behind a random port NAT
        let peer_average_delta_opt = peer_nat_info.get_average_delta_for_rand_port();

        // determine how we will connect to the peer
        match peer_nat_info {
            NatType::EIM(direct_addr, other_addrs, ..) => {
                let mut bands = Vec::new();
                // Below assumes the addr port is exactly whatever the server saw it as.
                // NOTE: since a QUIC connection may be established, using up the UDP port,
                // it is necessary that *before* the peer sends their info to this node, the port
                // is accurately reflected in this direct addr

                Self::load_alternate_bands(&mut bands, other_addrs.clone(), direct_addr.ip(), peer_declared_internal_port);

                // add the default external addr
                bands.push(AddrBand {
                    necessary_ip: direct_addr.ip(),
                    anticipated_ports: vec![peer_declared_internal_port]
                });

                let locally_bound_sockets = Self::generate_local_sockets(local_nat_info, first_local_socket)?;

                Ok(Self {
                    bands,
                    locally_bound_sockets: Some(locally_bound_sockets)
                })
            }

            NatType::PortPreserved(direct_addr, other_addrs, ..) => {
                let mut bands = Vec::new();
                // since there is no port translation, we assume the port below
                Self::load_alternate_bands(&mut bands, other_addrs.clone(), *direct_addr,peer_declared_internal_port);

                bands.push(AddrBand {
                    necessary_ip: *direct_addr,
                    anticipated_ports: vec![peer_declared_internal_port]
                });

                let locally_bound_sockets = Self::generate_local_sockets(local_nat_info, first_local_socket)?;

                Ok(Self {
                    bands,
                    locally_bound_sockets: Some(locally_bound_sockets)
                })
            }

            NatType::EDM(last_external_addr, other_addrs, delta, _) => {
                let mut bands = Vec::new();
                Self::generate_predict_ports_config(*delta as _, *last_external_addr, &mut bands, other_addrs.clone(), peer_declared_internal_port, local_nat_info);
                let locally_bound_sockets = Self::generate_local_sockets(local_nat_info, first_local_socket)?;

                Ok(Self {
                    bands,
                    locally_bound_sockets: Some(locally_bound_sockets)
                })
            }

            NatType::EDMRandomPort(last_external_addr, other_addrs, ..) => {
                let mut bands = Vec::new();
                let delta = peer_average_delta_opt.ok_or_else(||anyhow::Error::msg("Expected acceptable average delta"))?;
                Self::generate_predict_ports_config(delta, *last_external_addr, &mut bands, other_addrs.clone(), peer_declared_internal_port, local_nat_info);
                let locally_bound_sockets = Self::generate_local_sockets(local_nat_info, first_local_socket)?;

                Ok(Self {
                    bands,
                    locally_bound_sockets: Some(locally_bound_sockets)
                })
            }

            NatType::EDMRandomIp(_, _addr, _is_v6_allowed) => {
                // Thanks to the preceding logic, if we get here, we know the local node has a predictable address
                // evidently, the peer does not, however, this does not matter.
                // The packets we send likely will not make contact with the peer. However, once the peer
                // contacts us, we can then send a packet back to them. The peer will send packets to us at
                // the addr implicated by the first local socket. Thus, we keep the current socket, and,
                // create an empty send band

                // NOTE: the above assertion about the local node having a predictable addr
                // may not be true in localhost-testing mode. In the case we are in localhost-testing
                // mode, AND, both 'nodes' are behind an unpredictable NAT, simply connect to the internal
                // addr
                if cfg!(feature = "localhost-testing") {
                    log::trace!(target: "citadel", "Simulating peer has port preserved config");
                    // pretend the peer NAT has a PortPreserved config
                    let direct_addr = _addr.clone().ok_or_else(||anyhow::Error::msg("unable to simulate PortPreserved config"))?;
                    let simulated_peer_nat = NatType::PortPreserved(direct_addr.internal_ip, Some(direct_addr), *_is_v6_allowed);
                    Self::new(local_nat_info, &simulated_peer_nat, first_local_socket, peer_declared_internal_port)
                } else {
                    Ok(Self {
                        bands: vec![],
                        locally_bound_sockets: Some(vec![first_local_socket])
                    })
                }
            }

            NatType::EDMRandomIPPortPreserved(addrs, other_addrs, _) => {
                // the peer has semi-predictable addrs, each with a spread of 1
                // port is preserved, therefore, internal=external
                let first_addr = addrs[0];
                match first_addr {
                    IpAddr::V4(v4) => {
                        let mut octets = v4.octets();
                        let mut bands = vec![];

                        // use the first last external addr, mostly arbitrary
                        Self::load_alternate_bands(&mut bands, other_addrs.clone(), addrs[0], peer_declared_internal_port);

                        for _ in 0..4 {
                            // increment the last octet by 1
                            octets[3] = octets[3].wrapping_add(1);
                            bands.push(AddrBand { necessary_ip: IpAddr::from(octets), anticipated_ports: vec![peer_declared_internal_port] })
                        }

                        Ok(Self {
                            bands,
                            locally_bound_sockets: Some(vec![first_local_socket])
                        })
                    },

                    _ => {
                        Err(anyhow::Error::msg("Should not be an ipv6 addr in this block ..."))
                    }
                }
            }

            _ => {
                Err(anyhow::Error::msg("This function should not be called since one or more of the peers cannot be reached via STUN-like traversal"))
            }
        }
    }

    // `first_local_socket` is needed since it contains information vital for the adjacent node to connect,
    // especially if behind the same LAN. For maximum likelihood of NAT traversal, it is recommended that if
    // ipv6_is_enabled, the first_local_socket is also v6
    fn generate_local_sockets(
        _local_nat_info: &NatType,
        first_local_socket: UdpSocket,
    ) -> Result<Vec<UdpSocket>, anyhow::Error> {
        let ret = vec![first_local_socket];
        Ok(ret)
    }

    #[allow(dead_code)]
    fn generate_bind_for_delta_config(
        ret: &mut Vec<UdpSocket>,
        delta: u16,
        local_bind_addr: SocketAddr,
    ) -> Result<(), anyhow::Error> {
        // our internal port does not matter. The peer will predict the ports
        // we bind to. We will open SPREAD * delta ports locally since the peer will expect
        // that many ports to be open
        let delta = Self::check_delta(delta);
        let ports_to_bind_to = std::cmp::max(SPREAD * delta, 1);
        for _ in 0..ports_to_bind_to {
            ret.push(crate::socket_helpers::get_udp_socket(SocketAddr::new(
                local_bind_addr.ip(),
                0,
            ))?);
        }

        Ok(())
    }

    fn check_delta(delta: u16) -> u16 {
        // limit overflows when multiplying
        std::cmp::min(delta, 30)
    }

    fn generate_predict_ports_config(
        delta: u16,
        last_external_addr: SocketAddr,
        bands: &mut Vec<AddrBand>,
        other_addrs: Option<IpAddressInfo>,
        peer_declared_internal_port: u16,
        local_nat_type: &NatType,
    ) {
        // We need to generate a band of possible connect addrs. If delta = 5, then,
        // we create a band of delta * 6 possible connect addrs each with 1 port spacing
        // apart. The maximum delta is defined as 30, which means this may try pinging up to
        // 6 * 30 = 180 possible addresses
        // const SPREAD: u16 = 6;
        // if delta is zero (which would be odd), assume max of 1
        let delta = Self::check_delta(delta);
        let mut ports_to_target_count = std::cmp::max(SPREAD * delta, 1);

        if matches!(local_nat_type, NatType::PortPreserved(..)) {
            // since local's node is behind a predictable NAT, we don't have to worry about trying to
            // target the peer's NAT. Just add 1 target. This will help prevent flooding
            ports_to_target_count = 1;
        }

        // Note: with this type, it does NOT matter "where" the peer is bound to. To *predict* the port,
        // we take the port of the last_external_addr, then, begin incrementing at one above it to
        // ports_to_target_count
        let beginning_port = last_external_addr.port().wrapping_add(1);
        let ending_port = beginning_port.wrapping_add(ports_to_target_count);
        let ports = (beginning_port..ending_port).collect::<Vec<u16>>();

        Self::load_alternate_bands(
            bands,
            other_addrs,
            last_external_addr.ip(),
            peer_declared_internal_port,
        );

        // add the default external band
        // note: this ASSUMES last_external_addr is ipv4 (which it should be, since the NAT identification
        // subroutine uses STUNv4
        bands.push(AddrBand {
            necessary_ip: last_external_addr.ip(),
            anticipated_ports: ports,
        });
    }

    /// Loads alternate bands, assuming port preservation mostly accounting for internal LANS
    fn load_alternate_bands(
        bands: &mut Vec<AddrBand>,
        other_addrs: Option<IpAddressInfo>,
        last_external_addr: IpAddr,
        peer_declared_internal_port: u16,
    ) {
        // add the default alternate band
        if let Some(other_addrs) = other_addrs {
            let anticipated_ports = vec![peer_declared_internal_port];

            if other_addrs.internal_ip != last_external_addr {
                bands.push(AddrBand {
                    necessary_ip: other_addrs.internal_ip,
                    // note: Here, we don't use the external ports above. We use the internal one
                    // declared by the peer (note: this means the peer must deterministically generate this
                    // prior to sending its information here. This means it must first bind to a new UDP socket
                    // before sending over its information)
                    anticipated_ports: anticipated_ports.clone(),
                });
            }

            if let Some(external_v6) = other_addrs.external_ipv6 {
                if external_v6 != last_external_addr {
                    bands.push(AddrBand {
                        necessary_ip: external_v6,
                        // since this is an external v6 addr, we assume no need for port mapping
                        // (v6 addresses have no need for predictive NAT traversal). We can then assume a 1:1 port
                        // mapping from the peer declared internal port to its external port
                        anticipated_ports,
                    });
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct AddrBand {
    necessary_ip: IpAddr,
    anticipated_ports: Vec<u16>,
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

#[cfg(test)]
mod tests {
    use crate::nat_identification::NatType;
    use crate::udp_traversal::hole_punch_config::HolePunchConfig;
    use crate::udp_traversal::udp_hole_puncher::get_optimal_bind_socket;
    use async_ip::IpAddressInfo;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_hole_punch_config() {
        let dummy_addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        let dummy_ip0_ok = IpAddr::from_str("123.100.200.100").unwrap();
        let dummy_ip1_ok = IpAddr::from_str("123.100.200.101").unwrap();
        let dummy_ip2_ok = IpAddr::from_str("123.100.200.102").unwrap();
        let dummy_ip3_err = IpAddr::from_str("100.100.200.103").unwrap();

        let ip_addr_info_dummy = Some(IpAddressInfo {
            internal_ip: IpAddr::from([0, 0, 0, 0]),
            external_ipv6: None,
        });

        let eim = &NatType::EIM(dummy_addr, ip_addr_info_dummy.clone(), true);
        let edm = &NatType::EDM(dummy_addr, ip_addr_info_dummy.clone(), 1, true);
        let port_preserved =
            &NatType::PortPreserved(dummy_addr.ip(), ip_addr_info_dummy.clone(), true);
        let random_port_compat = &NatType::EDMRandomPort(
            dummy_addr,
            ip_addr_info_dummy.clone(),
            vec![10, 20, 30, 40],
            true,
        );
        let random_port_bad = &NatType::EDMRandomPort(
            dummy_addr,
            ip_addr_info_dummy.clone(),
            vec![40, 80, 120],
            true,
        );
        let random_ip =
            &NatType::EDMRandomIp(vec![dummy_addr.ip()], ip_addr_info_dummy.clone(), true);
        let random_ip_port_preserved_ok = &NatType::EDMRandomIPPortPreserved(
            vec![dummy_ip0_ok, dummy_ip1_ok, dummy_ip2_ok],
            ip_addr_info_dummy.clone(),
            true,
        );
        let random_ip_port_preserved_err = &NatType::EDMRandomIPPortPreserved(
            vec![dummy_ip0_ok, dummy_ip1_ok, dummy_ip3_err],
            ip_addr_info_dummy,
            true,
        );

        // Start with EIM
        inner_test(eim, eim);
        inner_test(eim, edm);
        inner_test(eim, port_preserved);
        inner_test(eim, random_port_compat);

        inner_test(eim, random_port_bad);
        inner_test(eim, random_ip);

        inner_test(eim, random_ip_port_preserved_ok);
        inner_test(eim, random_ip_port_preserved_err);

        // EDM
        inner_test(edm, edm);
        inner_test(edm, port_preserved);
        inner_test(edm, random_port_compat);

        inner_test(edm, random_port_bad);
        inner_test(edm, random_ip);
        inner_test(edm, random_ip_port_preserved_ok);
        inner_test(edm, random_ip_port_preserved_err);

        // PortPreserved
        inner_test(port_preserved, port_preserved);
        inner_test(port_preserved, random_port_compat);

        inner_test(port_preserved, random_port_bad);
        inner_test(port_preserved, random_ip);
        inner_test(port_preserved, random_ip_port_preserved_ok);
        inner_test(port_preserved, random_ip_port_preserved_err);

        // Random port (compat)
        inner_test(random_port_compat, random_port_compat);
        inner_test(random_port_compat, random_port_bad);
        inner_test(random_port_compat, random_ip);
        inner_test(random_port_compat, random_ip_port_preserved_ok);
        inner_test(random_port_compat, random_ip_port_preserved_err);

        // Random port (bad)
        inner_test(random_port_bad, random_ip_port_preserved_ok);

        // Random ip
        inner_test(random_ip, random_ip_port_preserved_ok);

        // random ip, port preserved, delta ok
        inner_test(random_ip_port_preserved_ok, random_ip_port_preserved_ok);
        inner_test(random_ip_port_preserved_ok, random_ip_port_preserved_err);
    }

    fn inner_test(local_nat_type: &NatType, peer_nat_type: &NatType) {
        assert!(local_nat_type.stun_compatible(peer_nat_type));
        let initial_socket_local = get_optimal_bind_socket(local_nat_type, peer_nat_type).unwrap();
        let internal_bind_port_local = initial_socket_local.local_addr().unwrap().port();

        let initial_socket_remote = get_optimal_bind_socket(peer_nat_type, local_nat_type).unwrap();
        let internal_bind_port_remote = initial_socket_remote.local_addr().unwrap().port();
        // TODO: assertions
        // local
        HolePunchConfig::new(
            local_nat_type,
            peer_nat_type,
            initial_socket_local,
            internal_bind_port_remote,
        )
        .unwrap();
        // remote
        HolePunchConfig::new(
            peer_nat_type,
            local_nat_type,
            initial_socket_remote,
            internal_bind_port_local,
        )
        .unwrap();
    }
}
