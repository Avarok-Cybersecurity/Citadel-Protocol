#![cfg_attr(feature = "localhost-testing-loopback-only", allow(unreachable_code))]

use crate::error::FirewallError;
use crate::socket_helpers::is_ipv6_enabled;
use async_ip::IpAddressInfo;
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::ops::Sub;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::udp_traversal::hole_punch_config::AddrBand;
use citadel_io::UdpSocket;
use stun::client::ClientBuilder;
use stun::message::{Getter, Message, BINDING_REQUEST};
use stun::xoraddr::XorMappedAddress;

const STUN_SERVERS: [&str; 3] = [
    "global.stun.twilio.com:3478",
    "stun1.l.google.com:19302",
    "stun4.l.google.com:19302",
];

const V4_BIND_ADDR: &str = "0.0.0.0:0";
const IDENTIFY_TIMEOUT: Duration = Duration::from_millis(4500);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum IpTranslation {
    /// The IP is the same
    Identity,
    /// The IP is translated, but, is invariant between outbound connections
    Constant { external: IpAddr },
    /// The IP is translated, and, is variant between outbound connections such that the NAT assigns
    /// an IP that is completely independent of the internal IP
    DeltaIndependentOffset {
        average_delta: i32,
        last_allocated_external_ip: IpAddr,
    },
    /// The IP is unpredictable
    #[default]
    Unpredictable,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum PortTranslation {
    /// The port remains the same between internal:external mappings
    Identity,
    /// The port is translated by a constant delta between internal:external mappings
    DeltaConstantOffset { delta: i32 },
    /// The port is translated invariantly between internal:external mappings such that the NAT assigns
    /// a port that is completely independent of the internal port
    DeltaIndependentOffset {
        average_delta: i32,
        last_allocated_external_port: u16,
    },
    /// The port is unpredictable
    #[default]
    Unpredictable,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NatType {
    pub ip_translation: IpTranslation,
    pub port_translation: PortTranslation,
    pub ip_info: Option<IpAddressInfo>,
    pub is_ipv6_enabled: bool,
}

pub struct SocketPair {
    pub internal: SocketAddr,
    pub external: SocketAddr,
}

pub const MAX_OCTET_DELTA: i32 = 5;

impl NatType {
    /// Identifies the NAT which the local node is behind. Timeout at the default (5s)
    /// `local_bind_addr`: Only relevant for localhost testing
    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(target = "citadel", skip_all, ret, err(Debug))
    )]
    pub async fn identify(stun_servers: Option<Vec<String>>) -> Result<Self, FirewallError> {
        Self::identify_timeout(IDENTIFY_TIMEOUT, stun_servers).await
    }

    /// Identifies the NAT which the local node is behind
    pub async fn identify_timeout(
        _timeout: Duration,
        stun_servers: Option<Vec<String>>,
    ) -> Result<Self, FirewallError> {
        match tokio::time::timeout(_timeout, get_nat_type(stun_servers)).await {
            Ok(res) => res
                .map_err(|err| FirewallError::HolePunch(err.to_string()))
                .map(|nat_type| {
                    *LOCALHOST_TESTING_NAT_TYPE.lock() = Some(nat_type.clone());
                    nat_type
                }),

            Err(_elapsed) => {
                log::warn!(target: "citadel", "Timeout on NAT identification occurred");
                if cfg!(feature = "localhost-testing") {
                    log::warn!(target: "citadel", "Will use default NatType for localhost-testing");
                    Ok(NatType {
                        ip_translation: IpTranslation::Identity,
                        port_translation: PortTranslation::Identity,
                        ip_info: Some(IpAddressInfo::localhost()),
                        is_ipv6_enabled: false,
                    })
                } else {
                    Err(FirewallError::HolePunch(
                        "NAT identification elapsed".to_string(),
                    ))
                }
            }
        }
    }

    pub fn new(addr0: SocketPair, addr1: SocketPair, addr2: SocketPair) -> Self {
        let ip_translation = Self::get_ip_translation(&addr0, &addr1, &addr2);
        let port_translation = Self::get_port_translation(&addr0, &addr1, &addr2);
        Self {
            ip_translation,
            port_translation,
            ip_info: None,
            is_ipv6_enabled: is_ipv6_enabled(),
        }
    }

    // given a local socket address, predicts the external addresses. Returns None if unpredictable
    pub(crate) fn predict(&self, internal_addr: &SocketAddr) -> Option<Vec<AddrBand>> {
        let mut bands = Vec::new();
        let internal_port = internal_addr.port();

        // These anticipated ports will be used for all ip translations
        let anticipated_ports = match self.port_translation {
            PortTranslation::Identity => vec![internal_port],
            PortTranslation::DeltaConstantOffset { delta } => {
                vec![Self::wrapping_port_add(internal_port, delta)]
            }
            PortTranslation::DeltaIndependentOffset {
                average_delta,
                last_allocated_external_port,
            } => {
                let mut ports = Vec::new();
                for i in average_delta..=(3 * average_delta) {
                    ports.push(Self::wrapping_port_add(last_allocated_external_port, i));
                }
                ports
            }
            PortTranslation::Unpredictable => return None,
        };

        // add the base IPs
        match self.ip_translation {
            IpTranslation::Identity => {
                let band = AddrBand {
                    necessary_ip: internal_addr.ip(),
                    anticipated_ports: anticipated_ports.clone(),
                };
                bands.push(band);
            }
            IpTranslation::Constant { external } => {
                let band = AddrBand {
                    necessary_ip: external,
                    anticipated_ports: anticipated_ports.clone(),
                };
                bands.push(band);
            }
            IpTranslation::DeltaIndependentOffset {
                average_delta,
                last_allocated_external_ip,
            } => {
                for i in average_delta..=(3 * average_delta) {
                    let next_ip = match last_allocated_external_ip {
                        IpAddr::V4(ip) => {
                            let mut octets = ip.octets();
                            octets[3] = octets[3].wrapping_add(i as u8);
                            IpAddr::from(octets)
                        }
                        IpAddr::V6(ip) => {
                            let mut octets = ip.octets();
                            octets[15] = octets[15].wrapping_add(i as u8);
                            IpAddr::from(octets)
                        }
                    };

                    let band = AddrBand {
                        necessary_ip: next_ip,
                        anticipated_ports: anticipated_ports.clone(),
                    };

                    bands.push(band);
                }
            }
            IpTranslation::Unpredictable => return None,
        }

        // finally, add the ipv6 band (if we have it)
        if let Some(ip_info) = &self.ip_info {
            if let Some(ext_ip) = &ip_info.external_ipv6 {
                let band = AddrBand {
                    necessary_ip: *ext_ip,
                    anticipated_ports: anticipated_ports.clone(),
                };
                bands.push(band);
            }

            // now, add the internal IP (potentially)
            if bands.iter().all(|r| r.necessary_ip != ip_info.internal_ip) {
                let band = AddrBand {
                    necessary_ip: ip_info.internal_ip,
                    anticipated_ports,
                };
                bands.push(band);
            }
        }

        // final case: nodes are on localhost
        // now, add the internal IP (potentially)
        if bands.iter().all(|r| {
            r.necessary_ip != internal_addr.ip() && !r.anticipated_ports.contains(&internal_port)
        }) {
            let band = AddrBand {
                necessary_ip: internal_addr.ip(),
                anticipated_ports: vec![internal_port],
            };
            bands.push(band);
        }

        Some(bands)
    }

    /// Given 3 socket addresses, determine the port translation
    fn get_ip_translation(
        addr0: &SocketPair,
        addr1: &SocketPair,
        addr2: &SocketPair,
    ) -> IpTranslation {
        let ip0_internal = addr0.internal.ip();
        let ip0_external = addr0.external.ip();
        let ip1_internal = addr1.internal.ip();
        let ip1_external = addr1.external.ip();
        let ip2_internal = addr2.internal.ip();
        let ip2_external = addr2.external.ip();

        if ip0_internal == ip0_external
            && ip1_internal == ip1_external
            && ip2_internal == ip2_external
        {
            return IpTranslation::Identity;
        }

        if ip0_external == ip1_external && ip1_external == ip2_external {
            return IpTranslation::Constant {
                external: ip0_external,
            };
        }

        let last_octet_external0 = Self::last_octet(&ip0_external);
        let last_octet_external1 = Self::last_octet(&ip1_external);
        let last_octet_external2 = Self::last_octet(&ip2_external);

        // Third case: NAT translates each ip's last octet independently
        // e.g., NAT may begin allocating at *.100, and incrementing upwards
        // e.g., [192.168.2.1] -> [192.168.2.100]
        // e.g., [192.168.2.2] -> [192.168.2.101]
        // e.g., [192.168.2.10] -> [192.168.2.102]
        // compare the external ip's last octet to find a pattern
        let last_external_octets = &[
            last_octet_external0,
            last_octet_external1,
            last_octet_external2,
        ];
        let average_delta = average_delta(last_external_octets);
        // if the delta is within an acceptable range, say, 5, then we can assume that the NAT is
        // potentially predictable
        if average_delta <= MAX_OCTET_DELTA as usize {
            let highest = *last_external_octets.iter().max().unwrap();

            let last_allocated_external_ip = if last_external_octets[0] == highest {
                ip0_external
            } else if last_external_octets[1] == highest {
                ip1_external
            } else {
                ip2_external
            };

            return IpTranslation::DeltaIndependentOffset {
                average_delta: average_delta as _,
                last_allocated_external_ip,
            };
        }

        IpTranslation::Unpredictable
    }

    fn get_port_translation(
        addr0: &SocketPair,
        addr1: &SocketPair,
        addr2: &SocketPair,
    ) -> PortTranslation {
        let port0_internal = addr0.internal.port();
        let port0_external = addr0.external.port();
        let port1_internal = addr1.internal.port();
        let port1_external = addr1.external.port();
        let port2_internal = addr2.internal.port();
        let port2_external = addr2.external.port();

        if port0_internal == port0_external
            && port1_internal == port1_external
            && port2_internal == port2_external
        {
            return PortTranslation::Identity;
        }

        let port0_delta = port0_external as i32 - port0_internal as i32;
        let port1_delta = port1_external as i32 - port1_internal as i32;
        let port2_delta = port2_external as i32 - port2_internal as i32;

        if port0_delta == port1_delta && port1_delta == port2_delta {
            return PortTranslation::DeltaConstantOffset { delta: port0_delta };
        }

        // last case: NAT translates each port's last octet independently
        // e.g., NAT may begin allocating at 25000, and incrementing upwards
        // e.g., 1098 > 25000
        // e.g., 10000 > 25001
        // e.g., 15000 > 25002
        let port_external_octets = &[port0_external, port1_external, port2_external];

        let average_delta = average_delta(port_external_octets);
        // if the delta is within an acceptable range, say, 5, then we can assume that the NAT predictably allocates ports
        if average_delta <= MAX_OCTET_DELTA as usize {
            let highest = *port_external_octets.iter().max().unwrap();

            let last_allocated_external_port = if port_external_octets[0] == highest {
                port0_external
            } else if port_external_octets[1] == highest {
                port1_external
            } else {
                port2_external
            };

            return PortTranslation::DeltaIndependentOffset {
                average_delta: average_delta as _,
                last_allocated_external_port,
            };
        }

        PortTranslation::Unpredictable
    }

    fn last_octet(ip: &IpAddr) -> u8 {
        match ip {
            IpAddr::V4(ip) => ip.octets()[3],
            IpAddr::V6(ip) => ip.octets()[15],
        }
    }

    fn wrapping_port_add(port: u16, delta: i32) -> u16 {
        let mut new_port = port.wrapping_add(delta as u16);
        if new_port < 1024 {
            new_port += 1024
        }

        new_port
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum TraversalTypeRequired {
    /// Use the linear hole punch subroutines in this crate
    Direct,
    /// direct p2p not possible
    TURN,
}

// we only need to check the NAT type once per node
lazy_static::lazy_static! {
    pub static ref LOCALHOST_TESTING_NAT_TYPE: citadel_io::Mutex<Option<NatType>> = citadel_io::Mutex::new(None);
}

impl NatType {
    /// Returns the NAT traversal type required to access self and other, respectively
    pub fn traversal_type_required_with(
        &self,
        other: &NatType,
    ) -> (TraversalTypeRequired, TraversalTypeRequired) {
        let this = self.traversal_type_required();
        let other = other.traversal_type_required();
        (this, other)
    }

    pub fn traversal_type_required(&self) -> TraversalTypeRequired {
        if matches!(self.ip_translation, IpTranslation::Unpredictable)
            || matches!(self.port_translation, PortTranslation::Unpredictable)
        {
            TraversalTypeRequired::TURN
        } else {
            TraversalTypeRequired::Direct
        }
    }

    /// If either of the method required to reach the endpoints don't require TURN, then the connection will work since at least one of the addrs is predictable
    ///
    /// Why? Suppose getting to node A requires unpredictable prediction, but, getting to node B does not.
    /// Node A can begin sending packets towards predictable B, where A binds towards any port internally.
    /// Simultaneously, like usual, node B send to A (however, it will likely send to the wrong address).
    /// Eventually, node A will send a packet correctly to node B. Node B will respond, taking note of the address
    /// like usual, and sending to the observed address. This observed address is where B will send packets to A.
    pub fn stun_compatible(&self, other_nat: &NatType) -> bool {
        let (this, other) = self.traversal_type_required_with(other_nat);
        this != TraversalTypeRequired::TURN || other != TraversalTypeRequired::TURN
    }

    pub fn ip_addr_info(&self) -> Option<&IpAddressInfo> {
        self.ip_info.as_ref()
    }

    pub fn is_ipv6_compatible(&self) -> bool {
        self.is_ipv6_enabled
    }
}

fn average_delta<T: Ord + Copy + Sized + Sub>(vals: impl AsRef<[T]>) -> usize
where
    usize: From<<T as Sub>::Output>,
{
    let vals = vals.as_ref().iter().copied().sorted().collect::<Vec<T>>();
    let count = vals.len() as f32;
    let sum_diff: usize = vals
        .into_iter()
        .tuple_windows()
        .map(|(a, b)| usize::from(b - a))
        .sum();
    let average = sum_diff as f32 / (count - 1f32);
    average.abs() as usize
}

#[cfg_attr(
    feature = "localhost-testing",
    tracing::instrument(target = "citadel", skip_all, ret, err(Debug))
)]
async fn get_nat_type(stun_servers: Option<Vec<String>>) -> Result<NatType, anyhow::Error> {
    let stun_servers = if let Some(stun_servers) = &stun_servers {
        Cow::Owned(stun_servers.iter().map(|r| r.as_str()).collect())
    } else {
        Cow::Borrowed(&STUN_SERVERS as &[&str])
    };

    let nat_type = async move {
        let mut msg = Message::new();
        msg.build(&[
            Box::<stun::agent::TransactionId>::default(),
            Box::new(BINDING_REQUEST),
        ])?;

        let msg = &msg;

        let futures_unordered = FuturesUnordered::new();

        for server in stun_servers.iter() {
            let task = async move {
                let udp_sck = UdpSocket::bind(V4_BIND_ADDR).await?;
                let new_bind_addr = udp_sck.local_addr()?;
                udp_sck.connect(server).await?;
                let (handler_tx, mut handler_rx) = tokio::sync::mpsc::unbounded_channel();
                log::trace!(target: "citadel", "Connected to STUN server {:?}", server);

                let mut client = ClientBuilder::new().with_conn(Arc::new(udp_sck)).build()?;

                client.send(msg, Some(Arc::new(handler_tx))).await?;

                if let Some(event) = handler_rx.recv().await {
                    match event.event_body {
                        Ok(msg) => {
                            let mut xor_addr = XorMappedAddress::default();
                            xor_addr.get_from(&msg)?;
                            let natted_addr = SocketAddr::new(xor_addr.ip, xor_addr.port);

                            log::trace!(target: "citadel", "External ADDR: {:?} | internal: {:?}", natted_addr, new_bind_addr);

                            return Ok(Some((natted_addr, new_bind_addr)));
                        }
                        Err(err) => log::trace!(target: "citadel", "{:?}", err),
                    };
                }

                Ok(None)
            };

            futures_unordered.push(Box::pin(task));
        }

        let mut results = futures_unordered
            .collect::<Vec<Result<Option<(SocketAddr, SocketAddr)>, anyhow::Error>>>()
            .await;
        let first_natted_addr = results
            .pop()
            .ok_or_else(|| anyhow::Error::msg("First result not present"))??;
        let second_natted_addr = results
            .pop()
            .ok_or_else(|| anyhow::Error::msg("Second result not present"))??;
        let third_natted_addr = results
            .pop()
            .ok_or_else(|| anyhow::Error::msg("Third result not present"))??;

        // now, we determine what the nat does when mapping internal socket addrs to external socket addrs
        match (first_natted_addr, second_natted_addr, third_natted_addr) {
            (
                Some((addr_ext, addr_int)),
                Some((addr2_ext, addr2_int)),
                Some((addr3_ext, addr3_int)),
            ) => {
                let pair0 = SocketPair {
                    internal: addr_int,
                    external: addr_ext,
                };
                let pair1 = SocketPair {
                    internal: addr2_int,
                    external: addr2_ext,
                };
                let pair2 = SocketPair {
                    internal: addr3_int,
                    external: addr3_ext,
                };

                let net_type = NatType::new(pair0, pair1, pair2);
                log::info!(target: "citadel", "NAT type: {:?}", net_type);

                Ok(net_type)
            }

            _ => Err(anyhow::Error::msg("Unable to get all three STUN addrs")),
        }
    };

    let ip_info_future = if cfg!(feature = "localhost-testing") {
        Box::pin(async move { Ok(Some(async_ip::IpAddressInfo::localhost())) })
            as Pin<
                Box<
                    dyn Future<Output = Result<Option<IpAddressInfo>, async_ip::IpRetrieveError>>
                        + Send,
                >,
            >
    } else {
        Box::pin(async move {
            match tokio::time::timeout(
                Duration::from_millis(1500),
                async_ip::get_all_multi_concurrent(None),
            )
            .await
            {
                Ok(Ok(ip_info)) => Ok(Some(ip_info)),
                Ok(Err(err)) => Err(err),
                Err(_) => Ok(None),
            }
        })
    };

    let (nat_type, ip_info) = tokio::join!(nat_type, ip_info_future);
    let mut nat_type = nat_type?;
    log::trace!(target: "citadel", "NAT Type: {nat_type:?} | IpInfo: {ip_info:?}");
    let ip_info = ip_info.map_err(|err| anyhow::Error::msg(err.to_string()))?;

    nat_type.ip_info = ip_info;
    Ok(nat_type)
}

#[cfg(test)]
mod tests {
    use crate::nat_identification::{
        IpTranslation, NatType, PortTranslation, SocketPair, MAX_OCTET_DELTA,
    };
    use crate::udp_traversal::hole_punch_config::AddrBand;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_identify() {
        citadel_logging::setup_log();
        let nat_type = NatType::identify(None).await.unwrap();
        let traversal_type = nat_type.traversal_type_required();
        log::trace!(target: "citadel", "NAT Type: {:?} | Reaching this node will require: {:?} NAT traversal | Hypothetical connect scenario", nat_type, traversal_type);
    }

    #[test]
    fn test_addr_translation_identification_identity_to_identity() {
        let addr0 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:10000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:10000").unwrap(),
        };

        let addr1 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:20000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:20000").unwrap(),
        };

        let addr2 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:30000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:30000").unwrap(),
        };

        let nat_type = NatType::new(addr0, addr1, addr2);
        assert!(matches!(nat_type.ip_translation, IpTranslation::Identity));
        assert!(matches!(
            nat_type.port_translation,
            PortTranslation::Identity
        ));

        let internal_addr = SocketAddr::from_str("192.168.2.1:30000").unwrap();
        let predicted_addrs = nat_type.predict(&internal_addr).unwrap();
        assert_eq!(
            predicted_addrs,
            vec![AddrBand {
                necessary_ip: internal_addr.ip(),
                anticipated_ports: vec![30000]
            }]
        );
    }

    #[test]
    fn test_addr_translation_identification_identity_to_delta_constant_offset() {
        let addr0 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:10000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:10010").unwrap(),
        };

        let addr1 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:20000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:20010").unwrap(),
        };

        let addr2 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:30000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:30010").unwrap(),
        };

        let nat_type = NatType::new(addr0, addr1, addr2);
        assert!(matches!(nat_type.ip_translation, IpTranslation::Identity));
        assert!(matches!(
            nat_type.port_translation,
            PortTranslation::DeltaConstantOffset { delta: 10 }
        ));
        let internal_addr = SocketAddr::from_str("192.168.2.1:30000").unwrap();
        let predicted_addrs = nat_type.predict(&internal_addr).unwrap();
        assert_eq!(
            predicted_addrs,
            vec![AddrBand {
                necessary_ip: internal_addr.ip(),
                anticipated_ports: vec![30010]
            }]
        );
    }

    #[test]
    // below the limit
    fn test_addr_translation_identification_identity_to_delta_independent_offset0() {
        let addr0 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:10000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:50000").unwrap(),
        };

        let addr1 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:20000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:50001").unwrap(),
        };

        let addr2 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:30000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:50002").unwrap(),
        };

        let nat_type = NatType::new(addr0, addr1, addr2);
        let _average_delta = 1;
        assert!(matches!(nat_type.ip_translation, IpTranslation::Identity));
        assert!(matches!(
            nat_type.port_translation,
            PortTranslation::DeltaIndependentOffset {
                average_delta: _average_delta,
                last_allocated_external_port: 50002
            }
        ));

        let internal_addr = SocketAddr::from_str("192.168.2.1:30000").unwrap();
        let predicted_addrs = nat_type.predict(&internal_addr).unwrap();
        assert_eq!(
            predicted_addrs,
            vec![AddrBand {
                necessary_ip: internal_addr.ip(),
                anticipated_ports: vec![50003, 50004, 50005]
            }]
        );
    }

    #[test]
    // at the limit
    fn test_addr_translation_identification_identity_to_delta_independent_offset1() {
        let mappings = [
            50000,
            50000 + MAX_OCTET_DELTA as u16,
            50000 + 2 * MAX_OCTET_DELTA as u16,
        ];

        let addr0 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:10000").unwrap(),
            external: SocketAddr::from_str(&format!("192.168.2.1:{}", mappings[0])).unwrap(),
        };

        let addr1 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:20000").unwrap(),
            external: SocketAddr::from_str(&format!("192.168.2.1:{}", mappings[1])).unwrap(),
        };

        let addr2 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:30000").unwrap(),
            external: SocketAddr::from_str(&format!("192.168.2.1:{}", mappings[2])).unwrap(),
        };

        let nat_type = NatType::new(addr0, addr1, addr2);
        let _last_allocated_external_port = mappings[2];
        assert!(matches!(nat_type.ip_translation, IpTranslation::Identity));
        assert!(matches!(
            nat_type.port_translation,
            PortTranslation::DeltaIndependentOffset {
                average_delta: MAX_OCTET_DELTA,
                last_allocated_external_port: _last_allocated_external_port
            }
        ));

        let internal_addr = SocketAddr::from_str("192.168.2.1:30000").unwrap();
        let predicted_addrs = nat_type.predict(&internal_addr).unwrap();
        assert_eq!(
            predicted_addrs,
            vec![AddrBand {
                necessary_ip: internal_addr.ip(),
                anticipated_ports: (50015u16..=50025u16).into_iter().collect()
            }]
        );
    }

    #[test]
    // above the limit
    fn test_addr_translation_identification_identity_to_delta_independent_offset2() {
        let mappings = [
            50000,
            50000 + 1u16 + MAX_OCTET_DELTA as u16,
            50000 + 2u16 + 2 * MAX_OCTET_DELTA as u16,
        ];

        let addr0 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:10000").unwrap(),
            external: SocketAddr::from_str(&format!("192.168.2.1:{}", mappings[0])).unwrap(),
        };

        let addr1 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:20000").unwrap(),
            external: SocketAddr::from_str(&format!("192.168.2.1:{}", mappings[1])).unwrap(),
        };

        let addr2 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:30000").unwrap(),
            external: SocketAddr::from_str(&format!("192.168.2.1:{}", mappings[2])).unwrap(),
        };

        let nat_type = NatType::new(addr0, addr1, addr2);
        let _last_allocated_external_port = mappings[2];
        assert!(matches!(nat_type.ip_translation, IpTranslation::Identity));
        assert!(matches!(
            nat_type.port_translation,
            PortTranslation::Unpredictable
        ));

        let internal_addr = SocketAddr::from_str("192.168.2.1:30000").unwrap();
        let predicted_addrs = nat_type.predict(&internal_addr);
        assert!(predicted_addrs.is_none());
    }

    #[test]
    fn test_addr_translation_identification_identity_to_unpredictable() {
        let addr0 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:10000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:10001").unwrap(),
        };

        let addr1 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:20000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:10500").unwrap(),
        };

        let addr2 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:30000").unwrap(),
            external: SocketAddr::from_str("192.168.2.1:16000").unwrap(),
        };

        let nat_type = NatType::new(addr0, addr1, addr2);
        assert!(matches!(nat_type.ip_translation, IpTranslation::Identity));
        assert!(matches!(
            nat_type.port_translation,
            PortTranslation::Unpredictable
        ));

        let internal_addr = SocketAddr::from_str("192.168.2.1:10000").unwrap();
        let predicted_addrs = nat_type.predict(&internal_addr);
        assert!(predicted_addrs.is_none());
    }

    #[test]
    fn test_addr_translation_identification_constant_to_identity() {
        let addr0 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:10000").unwrap(),
            external: SocketAddr::from_str("10.1.10.1:10000").unwrap(),
        };

        let addr1 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:20000").unwrap(),
            external: SocketAddr::from_str("10.1.10.1:20000").unwrap(),
        };

        let addr2 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:30000").unwrap(),
            external: SocketAddr::from_str("10.1.10.1:30000").unwrap(),
        };

        let nat_type = NatType::new(addr0, addr1, addr2);
        let _external = IpAddr::from_str("10.1.10.1").unwrap();
        assert!(matches!(
            nat_type.ip_translation,
            IpTranslation::Constant {
                external: _external
            }
        ));
        assert!(matches!(
            nat_type.port_translation,
            PortTranslation::Identity
        ));

        let internal_addr = SocketAddr::from_str("192.168.2.1:30000").unwrap();
        let predicted_addrs = nat_type.predict(&internal_addr).unwrap();
        assert_eq!(
            predicted_addrs,
            vec![AddrBand {
                necessary_ip: IpAddr::from_str("10.1.10.1").unwrap(),
                anticipated_ports: vec![30000]
            }]
        );
    }

    #[test]
    fn test_addr_translation_identification_delta_offset_to_identity() {
        let addr0 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:10000").unwrap(),
            external: SocketAddr::from_str("10.1.10.100:10000").unwrap(),
        };

        let addr1 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:20000").unwrap(),
            external: SocketAddr::from_str("10.1.10.101:20000").unwrap(),
        };

        let addr2 = SocketPair {
            internal: SocketAddr::from_str("192.168.2.1:30000").unwrap(),
            external: SocketAddr::from_str("10.1.10.102:30000").unwrap(),
        };

        let nat_type = NatType::new(addr0, addr1, addr2);
        let _last_allocated_external_ip = IpAddr::from_str("10.1.10.102").unwrap();
        assert!(matches!(
            nat_type.ip_translation,
            IpTranslation::DeltaIndependentOffset {
                average_delta: 1,
                last_allocated_external_ip: _last_allocated_external_ip
            }
        ));
        assert!(matches!(
            nat_type.port_translation,
            PortTranslation::Identity
        ));

        let internal_addr = SocketAddr::from_str("192.168.2.1:30000").unwrap();
        let predicted_addrs = nat_type.predict(&internal_addr).unwrap();
        assert_eq!(
            predicted_addrs,
            vec![
                AddrBand {
                    necessary_ip: IpAddr::from_str("10.1.10.103").unwrap(),
                    anticipated_ports: vec![30000]
                },
                AddrBand {
                    necessary_ip: IpAddr::from_str("10.1.10.104").unwrap(),
                    anticipated_ports: vec![30000],
                },
                AddrBand {
                    necessary_ip: IpAddr::from_str("10.1.10.105").unwrap(),
                    anticipated_ports: vec![30000],
                },
            ]
        );
    }
}
