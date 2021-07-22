use tokio::net::UdpSocket;
use std::net::{SocketAddr, IpAddr};
use stun::client::ClientBuilder;
use std::sync::Arc;
use stun::message::{Message, BINDING_REQUEST, Getter};
use stun::agent::TransactionId;
use stun::xoraddr::XorMappedAddress;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use serde::{Serialize, Deserialize};
use crate::error::FirewallError;
use std::time::Duration;

const STUN_SERVERS: [&str; 3] = ["global.stun.twilio.com:3478",
    "stun1.l.google.com:19302",
    "stun4.l.google.com:19302"
];

const V4_BIND_ADDR: &str = "0.0.0.0:0";
const IDENTIFY_TIMEOUT: Duration = Duration::from_millis(5000);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum NatType {
    /// ip_int:port_in == ip_ext:port_ext
    EIM(SocketAddr),
    /// Predictable Endpoint dependent Mapping NAT. Contains the detected delta.
    EDM(IpAddr, i32),
    /// Unpredictable Endpoint dependent Mapping NAT. Contains the detected IPs.
    EDMRandomIp(Vec<IpAddr>),
    /// Unpredictable Endpoint dependent Mapping NAT. Contains the detected ports.
    EDMRandomPort(IpAddr, Vec<u16>),
    /// Unknown or could not be determined
    Unknown,
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

impl Default for NatType {
    fn default() -> Self {
        NatType::Unknown
    }
}

impl NatType {
    /// Identifies the NAT which the local node is behind. Timeout at the default (5s)
    pub async fn identify() -> Result<Self, FirewallError> {
        tokio::time::timeout(IDENTIFY_TIMEOUT, get_nat_type()).await.map_err(|err| FirewallError::HolePunch(err.to_string()))?.map_err(|err| FirewallError::HolePunch(err.to_string()))
    }

    /// Identifies the NAT which the local node is behind
    pub async fn identify_timeout(timeout: Duration) -> Result<Self, FirewallError> {
        tokio::time::timeout(timeout, get_nat_type()).await.map_err(|err| FirewallError::HolePunch(err.to_string()))?.map_err(|err| FirewallError::HolePunch(err.to_string()))
    }

    /// Returns the NAT traversal type required to access self and other, respectively
    pub fn traversal_type_required_with(&self, other: &NatType) -> (TraversalTypeRequired, TraversalTypeRequired) {
        let this = self.traversal_type_required();
        let other = other.traversal_type_required();
        (this, other)
    }

    pub fn traversal_type_required(&self) -> TraversalTypeRequired {
        match self {
            NatType::EIM(..) => TraversalTypeRequired::Linear,
            NatType::EDM(_, 0) => TraversalTypeRequired::Linear,
            NatType::EDM(_, n) => TraversalTypeRequired::Delta(*n),
            _ => TraversalTypeRequired::TURN
        }
    }

    /// If either of the method required to reach the endpoints don't require TURN, then the connection will work since at least one of the addrs is predictable
    pub fn stun_compatible(&self, other: &NatType) -> bool {
        let (this, other) = self.traversal_type_required_with(other);
        this != TraversalTypeRequired::TURN || other != TraversalTypeRequired::TURN
    }

    /// Returns the local bind addr coupled with the implicated external connect addr
    ///
    /// When a peer A receives peer B's NatType, peer A should call this function to determine where to connect to
    pub fn get_connect_data(&self, local_port: u16) -> Option<(SocketAddr, SocketAddr)> {
        match self {
            Self::EIM(addr) => Some((*addr, *addr)),
            Self::EDM(ip_addr, delta) => Some((SocketAddr::new(IpAddr::from([0, 0, 0, 0]), local_port), SocketAddr::new(*ip_addr, (local_port as i32 + *delta) as u16))),
            _ => None
        }
    }

    pub fn predict_external_addr_from_local_bind_port(&self, local_bind_port: u16) -> Option<SocketAddr> {
        self.get_connect_data(local_bind_port).map(|r| r.1)
    }
}

async fn get_nat_type() -> Result<NatType, anyhow::Error> {
    let mut msg = Message::new();
    //msg.add(ATTR_CHANGE_REQUEST, b"Hello to the world!!!!!!");
    msg.build(&[
        Box::new(TransactionId::default()),
        Box::new(BINDING_REQUEST)
    ])?;

    //let init_socket = get_reuse_udp_socket::<(IpAddr, u16)>(None)?;
    //let bind_addr = init_socket.local_addr()?;

    //std::mem::drop(init_socket);

    let ref msg = msg;

    let futures_unordered = FuturesUnordered::new();

    for server in STUN_SERVERS.iter() {
        let task = async move {
            let udp_sck = UdpSocket::bind(V4_BIND_ADDR).await?;
            //let udp_sck = get_reuse_udp_socket(Some(bind_addr))?;
            let new_bind_addr = udp_sck.local_addr()?;
            let conn = Arc::new(udp_sck);
            conn.connect(server).await?;
            let (handler_tx, mut handler_rx) = tokio::sync::mpsc::unbounded_channel();
            log::info!("Connected to STUN server {:?}", server);

            let mut client = ClientBuilder::new().with_conn(conn.clone()).build()?;

            client.send(&msg, Some(Arc::new(handler_tx))).await?;

            if let Some(event) = handler_rx.recv().await {
                match event.event_body {
                    Ok(msg) => {
                        let mut xor_addr = XorMappedAddress::default();
                        xor_addr.get_from(&msg)?;
                        let natted_addr = SocketAddr::new(xor_addr.ip, xor_addr.port);

                        log::info!("Hole-punched ADDR: {:?} | internal: {:?}", natted_addr, new_bind_addr);

                        return Ok(Some((natted_addr, new_bind_addr)));
                    }
                    Err(err) => log::info!("{:?}", err),
                };
            }

            Ok(None)
        };

        futures_unordered.push(Box::pin(task));
    }

    let mut results = futures_unordered.collect::<Vec<Result<Option<(SocketAddr, SocketAddr)>, anyhow::Error>>>().await;
    let first_natted_addr = results.pop().ok_or(anyhow::Error::msg("First result not present"))??;
    let second_natted_addr = results.pop().ok_or(anyhow::Error::msg("Second result not present"))??;
    let third_natted_addr = results.pop().ok_or(anyhow::Error::msg("Third result not present"))??;

    // now, we determine what the nat does when mapping internal socket addrs to external socket addrs
    match (first_natted_addr, second_natted_addr, third_natted_addr) {
        (Some((addr_ext, addr_int)), Some((addr2_ext, addr2_int)), Some((addr3_ext, addr3_int))) => {
            // if there is zero changes in the mapping, then we have EIM
            if addr_ext == addr_int && addr2_ext == addr2_int && addr3_ext == addr3_int {
                // It doesn't matter where we connect; we always get the same socket addr
                return Ok(NatType::EIM(addr_ext));
            }

            // if the external IPs translated during the process, this is bad news
            if (addr_ext.ip() != addr2_ext.ip()) || (addr2_ext.ip() != addr3_ext.ip()) {
                // this is the worst nat type since ip's are unpredictable. Just use TURN
                return Ok(NatType::EDMRandomIp(vec![addr_ext.ip(), addr2_ext.ip(), addr3_ext.ip()]));
            }

            // ips are equal, but ports are unequal (implied by first conditional)
            let delta0 = i32::abs(addr_ext.port() as i32 - addr_int.port() as i32);
            let delta1 = i32::abs(addr2_ext.port() as i32 - addr2_int.port() as i32);
            let delta2 = i32::abs(addr3_ext.port() as i32 - addr3_int.port() as i32);
            log::info!("Delta0: {} | Delta1: {} | Delta2: {}", delta0, delta1, delta2);

            return if (delta0 == delta1) && (delta1 == delta2) {
                // This means the ports are predictable. Use TCP simultaneous connect on expected ports based on delta. It is expected this data be sent to the peer. The peer will then connect to the socket ip:(LOCAL_BIND_PORT+delta)
                Ok(NatType::EDM(addr_ext.ip(), delta0))
            } else {
                // the IP's are equal, but, the ports are not predictable; use TURN
                Ok(NatType::EDMRandomPort(addr_ext.ip(), vec![addr_ext.port(), addr2_ext.port(), addr3_ext.port()]))
            };
        }

        _ => {
            Err(anyhow::Error::msg("Unable to get both STUN addrs"))
        }
    }
}

/*
fn get_reuse_udp_socket<T: std::net::ToSocketAddrs>(addr: Option<T>) -> Result<UdpSocket, anyhow::Error> {
    let addr: SocketAddr = if let Some(addr) = addr {
        addr.to_socket_addrs()?.next().ok_or(anyhow::Error::msg("No sockets"))?
    } else {
        SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0)
    };

    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        {
            use net2::unix::UnixUdpBuilderExt;

            let builder = net2::UdpBuilder::new_v4()?;
            Ok(builder.reuse_address(true)?.reuse_port(true)?.bind(addr).and_then(|r| {
                r.set_nonblocking(true)?;
                tokio::net::UdpSocket::from_std(r)
            })?)
        }
    #[cfg(not(all(unix, not(any(target_os = "solaris", target_os = "illumos")))))]
        {
            let builder = net2::UdpBuilder::new_v4()?;
            Ok(builder.reuse_address(true)?.bind(addr).and_then(|r| {
                r.set_nonblocking(true)?;
                tokio::net::UdpSocket::from_std(r)
            })?)
        }
}*/

#[cfg(test)]
mod tests {
    use crate::nat_identification::{NatType, get_routelen_to};
    use std::time::Duration;

    fn setup_log() {
        std::env::set_var("RUST_LOG", "error,warn,info,trace");
        //std::env::set_var("RUST_LOG", "error");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[tokio::test]
    async fn main() {
        setup_log();
        let nat_type = NatType::identify().await.unwrap();
        let traversal_type = nat_type.traversal_type_required();
        let connect_data = nat_type.get_connect_data(25000);
        log::info!("NAT Type: {:?} | Reaching this node will require: {:?} NAT traversal | Hypothetical connect scenario: {:?}", nat_type, traversal_type, connect_data);
    }
}