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
pub(crate) const MAX_PORT_DELTA_FOR_PREDICTION: usize = 30;
pub(crate) const MAX_LAST_OCTET_DELTA_FOR_PREDICTION: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum NatType {
    /// ip_int:port_in == ip_ext:port_ext
    EIM(SocketAddr, Option<IpAddressInfo>, bool),
    /// Does not matter "where" the node connects to: the ip translates, but, the port stays the same
    PortPreserved(IpAddr, Option<IpAddressInfo>, bool),
    /// Predictable Endpoint dependent Mapping NAT. Contains the detected delta.
    EDM(SocketAddr, Option<IpAddressInfo>, i32, bool),
    /// Unpredictable Endpoint dependent Mapping NAT. Contains the detected IPs.
    EDMRandomIp(Vec<IpAddr>, Option<IpAddressInfo>, bool),
    /// IP translates, yet, port is preserved between internal:external
    EDMRandomIPPortPreserved(Vec<IpAddr>, Option<IpAddressInfo>, bool),
    /// Possibly unpredictable Endpoint dependent Mapping NAT. Contains the detected ports.
    EDMRandomPort(SocketAddr, Option<IpAddressInfo>, Vec<u16>, bool),
    /// Unknown or could not be determined
    #[default]
    Unknown,
}

pub enum IpTranslation {
    /// The IP is the same
    Identity { addr: IpAddr },
    /// The IP is translated, but, is invariant between outbound connections
    Constant { internal: IpAddr, external: IpAddr },
    /// The IP is translated, and, is variant between outbound connections by a constant delta
    DeltaConstantOffset {
        internal: IpAddr,
        external: IpAddr,
        delta: i32,
    },
    /// The IP is translated, and, is variant between outbound connections such that the NAT assigns
    /// an IP that is completely independent of the internal port
    DeltaIndependentOffset {
        internal: IpAddr,
        external: IpAddr,
        last_allocated_external_port: u16,
    },
}

pub enum PortTranslation {
    /// The port remains the same between internal:external mappings
    Identity { port: u16 },
    /// The port is translated by a constant delta between internal:external mappings
    DeltaConstantOffset { port: u16, delta: i32 },
    /// The port is translated invariantly between internal:external mappings such that the NAT assigns
    /// a port that is completely independent of the internal port
    DeltaIndependentOffset { last_allocated_external_port: u16 },
}

pub struct NatTypeV2 {
    pub ip_translation: IpTranslation,
    pub port_translation: PortTranslation,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum TraversalTypeRequired {
    /// Use the linear hole punch subroutines in this crate
    Linear,
    /// Use the linear hole punch subroutines in this crate with adjusted port params
    Delta(i32),
    /// direct p2p not possible
    TURN,
}

// we only need to check the NAT type once per node
lazy_static::lazy_static! {
    pub static ref LOCALHOST_TESTING_NAT_TYPE: citadel_io::Mutex<Option<NatType>> = citadel_io::Mutex::new(None);
}

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
        /*
        #[cfg(feature = "localhost-testing-loopback-only")]
        {
            let lock = LOCALHOST_TESTING_NAT_TYPE.lock();
            if let Some(nat_type) = lock.clone() {
                log::warn!(target: "citadel", "Will not detect NAT type since local already has it: {:?}", nat_type);
                return Ok(nat_type);
            }
        }*/
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
                    Ok(NatType::PortPreserved(
                        IpAddr::from([127, 0, 0, 1]),
                        None,
                        false,
                    ))
                } else {
                    Err(FirewallError::HolePunch(
                        "NAT identification elapsed".to_string(),
                    ))
                }
            }
        }
    }

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
        match self {
            NatType::EIM(..) => TraversalTypeRequired::Linear,
            NatType::PortPreserved(..) => TraversalTypeRequired::Linear,
            NatType::EDM(_, _, n, _) => TraversalTypeRequired::Delta(*n),
            NatType::EDMRandomPort(_, _, _ports, _) => {
                let average_delta = self.get_average_delta_for_rand_port().unwrap();
                if average_delta > MAX_PORT_DELTA_FOR_PREDICTION as _ {
                    TraversalTypeRequired::TURN
                } else {
                    TraversalTypeRequired::Delta(average_delta as _)
                }
            }

            NatType::EDMRandomIPPortPreserved(addrs, _, _) => {
                let mut octets: Vec<[u8; 4]> = vec![];
                for addr in addrs {
                    match addr {
                        IpAddr::V4(v4) => octets.push(v4.octets()),

                        IpAddr::V6(_) => {
                            // in this case, we assume the v6 addr is stable, and,
                            // return as traversable (this should be unreachable in prod code)
                            return TraversalTypeRequired::Linear;
                        }
                    }
                }

                let delta = average_delta(&octets.iter().map(|r| r[3]).collect::<Vec<u8>>());
                if delta < MAX_LAST_OCTET_DELTA_FOR_PREDICTION {
                    // make sure the first three octets of every ip are equivalent
                    if octets
                        .iter()
                        .map(|r| Vec::from(&r[0..3] as &[u8]))
                        .all_equal()
                    {
                        TraversalTypeRequired::Delta(delta as _)
                    } else {
                        TraversalTypeRequired::TURN
                    }
                } else {
                    // IP is too
                    TraversalTypeRequired::TURN
                }
            }
            NatType::EDMRandomIp(..) | NatType::Unknown => TraversalTypeRequired::TURN,
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
        match self {
            NatType::EIM(_, ip, _)
            | NatType::EDM(_, ip, ..)
            | NatType::PortPreserved(_, ip, _)
            | NatType::EDMRandomIp(_, ip, _)
            | NatType::EDMRandomIPPortPreserved(_, ip, _)
            | NatType::EDMRandomPort(_, ip, _, _) => ip.as_ref(),
            NatType::Unknown => None,
        }
    }

    pub fn get_average_delta_for_rand_port(&self) -> Option<u16> {
        match self {
            Self::EDMRandomPort(_, _, ports, _) => {
                let average = average_delta(ports);
                Some(average as _)
            }

            _ => None,
        }
    }

    pub fn is_ipv6_compatible(&self) -> bool {
        match self {
            NatType::EIM(_, _, v6)
            | NatType::PortPreserved(_, _, v6)
            | NatType::EDM(_, _, _, v6)
            | NatType::EDMRandomIp(_, _, v6)
            | NatType::EDMRandomIPPortPreserved(_, _, v6)
            | NatType::EDMRandomPort(_, _, _, v6) => *v6,
            NatType::Unknown => false,
        }
    }

    fn store_ip_info(&mut self, info: Option<IpAddressInfo>) {
        if let Some(info) = info {
            match self {
                NatType::PortPreserved(_, ip, _)
                | NatType::EIM(_, ip, _)
                | NatType::EDM(_, ip, ..)
                | NatType::EDMRandomIp(_, ip, _)
                | NatType::EDMRandomIPPortPreserved(_, ip, _)
                | NatType::EDMRandomPort(_, ip, _, _) => *ip = Some(info),
                NatType::Unknown => {}
            }
        }
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
        let is_ipv6_allowed = is_ipv6_enabled();

        // now, we determine what the nat does when mapping internal socket addrs to external socket addrs
        match (first_natted_addr, second_natted_addr, third_natted_addr) {
            (
                Some((addr_ext, addr_int)),
                Some((addr2_ext, addr2_int)),
                Some((addr3_ext, addr3_int)),
            ) => {
                let port_preserved = addr_ext.port() == addr_int.port()
                    && addr2_ext.port() == addr2_int.port()
                    && addr3_ext.port() == addr3_int.port();
                // if there is zero changes in the mapping, then we have EIM
                if addr_ext == addr_int && addr2_ext == addr2_int && addr3_ext == addr3_int {
                    // It doesn't matter where we connect; we always get the same socket addr
                    return Ok(NatType::EIM(addr_ext, None, is_ipv6_allowed));
                }

                // if ANY addrs are v6, then NAT traversal to this node should be easy
                if let Some(v6_addr) = [addr_ext, addr2_ext, addr3_ext]
                    .iter()
                    .find(|r| r.is_ipv6())
                {
                    return Ok(NatType::EIM(*v6_addr, None, is_ipv6_allowed));
                }

                // if the external IPs translated during the process, this may not be good for addr prediction
                if (addr_ext.ip() != addr2_ext.ip()) || (addr2_ext.ip() != addr3_ext.ip()) {
                    // Check to see if the first three octets are all the same
                    match (addr_ext, addr2_ext, addr3_ext) {
                        (SocketAddr::V4(v4_0), SocketAddr::V4(v4_1), SocketAddr::V4(v4_2)) => {
                            if v4_0.ip().octets()[..3] == v4_1.ip().octets()[..3]
                                && v4_1.ip().octets()[..3] == v4_2.ip().octets()[..3]
                            {
                                // first three octets are equivalent. Check to see if port preservation is true
                                if port_preserved {
                                    // check to make sure the average delta is
                                    if average_delta(&vec![
                                        v4_0.ip().octets()[3],
                                        v4_0.ip().octets()[3],
                                        v4_0.ip().octets()[3],
                                    ]) < MAX_LAST_OCTET_DELTA_FOR_PREDICTION
                                    {
                                        return Ok(NatType::EDMRandomIPPortPreserved(
                                            vec![addr_ext.ip(), addr2_ext.ip(), addr3_ext.ip()],
                                            None,
                                            is_ipv6_allowed,
                                        ));
                                    }
                                }
                            }
                        }

                        _ => {
                            unreachable!("Ipv6 addrs block should have returned already")
                        }
                    }
                    // this is the worst nat type since ip's are unpredictable. Just use TURN if other is random IP,
                    // unless, the other has a predictable addr
                    return Ok(NatType::EDMRandomIp(
                        vec![addr_ext.ip(), addr2_ext.ip(), addr3_ext.ip()],
                        None,
                        is_ipv6_allowed,
                    ));
                }

                // check to see if ext_port == int_port
                if port_preserved {
                    // in this case, the IP changes, however, the port stays the same. The NAT maps as such:
                    // ip0:port -> ip1:port
                    return Ok(NatType::PortPreserved(addr_ext.ip(), None, is_ipv6_allowed));
                }

                let deltas = &mut [addr_ext.port(), addr2_ext.port(), addr3_ext.port()];
                deltas.sort_unstable();

                let delta0 = i32::abs(deltas[0] as i32 - deltas[1] as i32);
                let delta1 = i32::abs(deltas[1] as i32 - deltas[2] as i32);
                log::trace!(target: "citadel", "[external] Delta0: {} | Delta1: {}", delta0, delta1);

                let highest_latest_port = deltas[2];
                let highest_last_addr = SocketAddr::new(addr_ext.ip(), highest_latest_port);

                if delta0 == delta1 {
                    // This means the ports are predictable. Use TCP simultaneous connect on expected ports based on delta. It is expected this data be sent to the peer. The peer will then connect to the socket ip:(LOCAL_BIND_PORT+delta)
                    Ok(NatType::EDM(
                        highest_last_addr,
                        None,
                        delta0,
                        is_ipv6_allowed,
                    ))
                } else {
                    // the IP's are equal, but, the ports are not predictable; use TURN
                    Ok(NatType::EDMRandomPort(
                        highest_last_addr,
                        None,
                        vec![addr_ext.port(), addr2_ext.port(), addr3_ext.port()],
                        is_ipv6_allowed,
                    ))
                }
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

    nat_type.store_ip_info(ip_info);
    Ok(nat_type)
}

#[cfg(test)]
mod tests {
    use crate::nat_identification::NatType;
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
    fn test_average_delta_computation() {
        assert_average_delta_inner(vec![70, 10, 50, 30], 20);
        assert_average_delta_inner(vec![10, 30, 50, 70], 20);
        assert_average_delta_inner(vec![10, 30, 50, 70, 90, 110], 20);
        assert_average_delta_inner(vec![1, 2, 3, 4, 5, 6], 1);
        assert_average_delta_inner(vec![2, 4, 6, 8, 10, 12], 2);
    }

    fn assert_average_delta_inner(ports: Vec<u16>, expected: u16) {
        let dummy_nat_type = NatType::EDMRandomPort(
            SocketAddr::from_str("127.0.0.1:1234").unwrap(),
            None,
            ports,
            false,
        );
        assert_eq!(
            expected,
            dummy_nat_type.get_average_delta_for_rand_port().unwrap()
        )
    }

    #[test]
    fn test_nat_traversal_compat() {
        let dummy_addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        let dummy_ip0_ok = IpAddr::from_str("123.100.200.100").unwrap();
        let dummy_ip1_ok = IpAddr::from_str("123.100.200.101").unwrap();
        let dummy_ip2_ok = IpAddr::from_str("123.100.200.102").unwrap();
        let dummy_ip3_err = IpAddr::from_str("100.100.200.103").unwrap();

        let eim = &NatType::EIM(dummy_addr, None, true);
        let edm = &NatType::EDM(dummy_addr, None, 1, true);
        let port_preserved = &NatType::PortPreserved(dummy_addr.ip(), None, true);
        let random_port_compat =
            &NatType::EDMRandomPort(dummy_addr, None, vec![10, 20, 30, 40], true);
        let random_port_bad = &NatType::EDMRandomPort(dummy_addr, None, vec![40, 80, 120], true);
        let random_ip = &NatType::EDMRandomIp(vec![dummy_addr.ip()], None, true);
        let random_ip_port_preserved_ok = &NatType::EDMRandomIPPortPreserved(
            vec![dummy_ip0_ok, dummy_ip1_ok, dummy_ip2_ok],
            None,
            true,
        );
        let random_ip_port_preserved_err = &NatType::EDMRandomIPPortPreserved(
            vec![dummy_ip0_ok, dummy_ip1_ok, dummy_ip3_err],
            None,
            true,
        );

        // Start with EIM
        inner_nat_traversal_compat(eim, eim, true);
        inner_nat_traversal_compat(eim, edm, true);
        inner_nat_traversal_compat(eim, port_preserved, true);
        inner_nat_traversal_compat(eim, random_port_compat, true);

        inner_nat_traversal_compat(eim, random_port_bad, true);
        inner_nat_traversal_compat(eim, random_ip, true);

        inner_nat_traversal_compat(eim, random_ip_port_preserved_ok, true);
        inner_nat_traversal_compat(eim, random_ip_port_preserved_err, true);

        // EDM
        inner_nat_traversal_compat(edm, edm, true);
        inner_nat_traversal_compat(edm, port_preserved, true);
        inner_nat_traversal_compat(edm, random_port_compat, true);

        inner_nat_traversal_compat(edm, random_port_bad, true);
        inner_nat_traversal_compat(edm, random_ip, true);
        inner_nat_traversal_compat(edm, random_ip_port_preserved_ok, true);
        inner_nat_traversal_compat(edm, random_ip_port_preserved_err, true);

        // PortPreserved
        inner_nat_traversal_compat(port_preserved, port_preserved, true);
        inner_nat_traversal_compat(port_preserved, random_port_compat, true);

        inner_nat_traversal_compat(port_preserved, random_port_bad, true);
        inner_nat_traversal_compat(port_preserved, random_ip, true);
        inner_nat_traversal_compat(port_preserved, random_ip_port_preserved_ok, true);
        inner_nat_traversal_compat(port_preserved, random_ip_port_preserved_err, true);

        // Random port (compat)
        inner_nat_traversal_compat(random_port_compat, random_port_compat, true);
        inner_nat_traversal_compat(random_port_compat, random_port_bad, true);
        inner_nat_traversal_compat(random_port_compat, random_ip, true);
        inner_nat_traversal_compat(random_port_compat, random_ip_port_preserved_ok, true);
        inner_nat_traversal_compat(random_port_compat, random_ip_port_preserved_err, true);

        // Random port (bad)
        inner_nat_traversal_compat(random_port_bad, random_port_bad, false);
        inner_nat_traversal_compat(random_port_bad, random_ip, false);
        inner_nat_traversal_compat(random_port_bad, random_ip_port_preserved_ok, true);
        inner_nat_traversal_compat(random_port_bad, random_ip_port_preserved_err, false);

        // Random ip
        inner_nat_traversal_compat(random_ip, random_ip, false);
        inner_nat_traversal_compat(random_ip, random_ip_port_preserved_ok, true);
        inner_nat_traversal_compat(random_ip, random_ip_port_preserved_err, false);

        // random ip, port preserved, delta ok
        inner_nat_traversal_compat(
            random_ip_port_preserved_ok,
            random_ip_port_preserved_ok,
            true,
        );
        inner_nat_traversal_compat(
            random_ip_port_preserved_ok,
            random_ip_port_preserved_err,
            true,
        );

        // random ip, port preserved, delta bad
        inner_nat_traversal_compat(
            random_ip_port_preserved_err,
            random_ip_port_preserved_err,
            false,
        );
    }

    fn inner_nat_traversal_compat(ty1: &NatType, ty2: &NatType, stun_compat: bool) {
        // also prove comparisons are commutative
        assert_eq!(stun_compat, ty1.stun_compatible(ty2));
        assert_eq!(stun_compat, ty2.stun_compatible(ty1));
    }
}
