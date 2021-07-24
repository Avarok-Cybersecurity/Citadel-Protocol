use async_trait::async_trait;
use std::net::SocketAddr;
use crate::error::FirewallError;
use crate::udp_traversal::linear::method3::Method3;
use crate::udp_traversal::hole_punched_udp_socket_addr::{HolePunchedSocketAddr, HolePunchedUdpSocket};
use tokio::net::UdpSocket;
use crate::udp_traversal::NatTraversalMethod;
use crate::upnp_handler::UPnPHandler;
use tokio::time::Duration;
use igd::PortMappingProtocol;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;

pub mod encrypted_config_container;

pub mod method1;
pub mod method3;
pub mod multi_delta;

/// Whereas UDP hole punching usually entails the connection between two peers (p2p),
/// linear UDP hole punching is the process of punching a hole through the firewall to allow
/// the server to reach a single client behind a NAT. The pre-process begins with sending a SYN followed
/// by its local timestamp (UTC; globally synchronized). The receiving end then calculates the ping,
/// sends a SYN_ACK packet, then waits for a duration equal to 1.0x the ping. This concludes stage 0 of the
/// linear hole punch subroutine. Thereafter, the [UdpHolePunchImpl] should be executed clientside. On the
/// receiver end, the [UdpHolePunchImpl] should be called once the CONNECT process ends for the receiver
///
/// It is the duty of the API user to execute the pre-process BEFORE asynchronously calling this
///
/// Note: The [LinearUDPHolePuncher] should only be used when a client, behind either a residential or
/// cellular NAT, is connecting to a globally-routable server
pub struct SingleUDPHolePuncher {
    method3: (bool, Method3),
    upnp_handler: (bool, Option<UPnPHandler>),
    socket: Option<UdpSocket>,
    possible_endpoints: Vec<SocketAddr>,
    #[allow(dead_code)]
    relative_node_type: RelativeNodeType,
    local_bind_addr: SocketAddr
}

impl SingleUDPHolePuncher {

    /// This assumes STUN has already been used. In the case of HYXE networks, since the central server
    /// proxies information anyways, the holes will only need to be punched when the central server needs
    /// to communicate with the client through UDP. Client to server UDP works almost guaranteed, but not
    /// the other way around in the case with carrier grade or symmetric NATs.
    ///
    /// `peer_addr`: This should be the addr where the server/client is already connected to (external addr). It is assumed that this already has a hole in the NAT
    pub fn new_initiator(encrypted_config_container: EncryptedConfigContainer, local_bind_addr: SocketAddr, peer_external_addr: SocketAddr, peer_internal_addr: SocketAddr) -> Result<Self, anyhow::Error> {
        Self::new(RelativeNodeType::Initiator, encrypted_config_container,  local_bind_addr, peer_external_addr, peer_internal_addr)
    }

    pub fn new_receiver(encrypted_config_container: EncryptedConfigContainer, local_bind_addr: SocketAddr, peer_external_addr: SocketAddr, peer_internal_addr: SocketAddr) -> Result<Self, anyhow::Error> {
        Self::new(RelativeNodeType::Receiver,  encrypted_config_container, local_bind_addr, peer_external_addr, peer_internal_addr)
    }

    pub fn new(relative_node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer, local_bind_addr: SocketAddr, peer_external_addr: SocketAddr, peer_internal_addr: SocketAddr) -> Result<Self, anyhow::Error> {
        log::info!("Setting up single-udp hole-puncher. Local bind addr: {:?} | Peer External Addr: {:?} | Peer Internal Addr: {:?}", local_bind_addr, peer_external_addr, peer_internal_addr);

        let method3= Method3::new(relative_node_type, encrypted_config_container);
        let socket = crate::socket_helpers::get_reuse_udp_socket(local_bind_addr)?;
        //let external_predicted_addr = peer_external_addr;
        //let internal_addr = adjacent_peer_nat.internal_ip().ok_or_else(|| anyhow::Error::msg("Peer does not have a valid internal IP"))?;

        let possible_endpoints = if peer_internal_addr == peer_external_addr {
            vec![peer_external_addr]
        } else {
            vec![peer_external_addr, peer_internal_addr]
        };

        Ok(Self { method3: (false, method3), upnp_handler: (false, None), socket: Some(socket), possible_endpoints, relative_node_type, local_bind_addr })
    }

    pub fn take_socket(&mut self) -> Option<UdpSocket> {
        self.socket.take()
    }

    /// During pre-connect stage 0 (initiator) AND stage 1 (receiver), this should be called to share the socket information
    /// with the other side. This is preferred, as it also configures the local firewall to allow all inbound/outbound traffic
    /// on these ports
    /*
    fn reserve_new_udp_sockets<T: Into<IpAddr>>(count: usize, bind_addr: T) -> Result<Vec<UdpSocket>, FirewallError> {
        let bind_addr = bind_addr.into();
        let result = (0..count).into_iter().map(|_| -> Result<UdpSocket, std::io::Error> {
            let socket = std::net::UdpSocket::bind(SocketAddr::new(bind_addr, 0))?;
            // on android, the below will fail since sudo access is not permissible
            if let Err(err) = open_local_firewall_port(FirewallProtocol::UDP(socket.local_addr()?.port())) {
                log::warn!("Unable to ensure UDP ports were opened. Packets may not traverse ({})", err.to_string());
            }

            socket.set_nonblocking(true)?;

            log::info!("Reserved UDP socket on local socket {:?}", &socket);
            UdpSocket::from_std(socket)
        }).filter_map(|res| {
            res.ok()
        }).collect::<Vec<UdpSocket>>();

        if result.len() != count {
            Err(FirewallError::HolePunch("We were unable to setup the UDP sockets. Ensure you have valid permissions and try again".to_string()))
        } else {
            Ok(result)
        }
    }*/

    //
    pub async fn try_method(&mut self, method: NatTraversalMethod) -> Result<HolePunchedUdpSocket, FirewallError> {
        match method {
            NatTraversalMethod::UPnP => {
                self.upnp_handler.0 = true;

                if self.upnp_handler.1.is_none() {
                    self.upnp_handler.1 = Some(UPnPHandler::new(Some(Duration::from_millis(2000))).await?);
                }

                let handler = self.upnp_handler.1.as_ref().unwrap();
                let local_addr = self.socket.as_ref().ok_or_else(||FirewallError::HolePunch("UDP Socket not loaded".to_string()))?.local_addr()?;
                let reserved_port = handler.open_any_firewall_port(PortMappingProtocol::UDP, None, "Lusna", None, local_addr.port()).await?;
                //let reserved_port = handler.open_any_firewall_port(PortMappingProtocol::TCP, None, "SatoriNET", None, local_socket.local_addr()?.port()).await?;
                let peer_external_addr = self.peer_external_addr(); // the external addr is in slot 0
                // The return address will appear as the natted socket below because the adjacent endpoint must send through the reserve port
                let natted_socket = SocketAddr::new(peer_external_addr.ip(), reserved_port);
                log::info!("[UPnP]: Opened port {}", reserved_port);
                let hole_punched_addr = HolePunchedSocketAddr::new(peer_external_addr, natted_socket, local_addr);
                log::info!("[UPnP] {}", &hole_punched_addr);

                Ok(HolePunchedUdpSocket { addr: hole_punched_addr, socket: self.socket.take().ok_or_else(|| FirewallError::HolePunch("UDP socket not loaded".to_string()))? })
            },

            NatTraversalMethod::Method3 => {
                self.method3.0 = true;
                let addr = self.method3.1.execute(self.socket.as_ref().ok_or_else(|| FirewallError::HolePunch("UDP socket not loaded".to_string()))?, &self.possible_endpoints).await?;
                Ok(HolePunchedUdpSocket { socket: self.socket.take().unwrap(), addr })
            },

            NatTraversalMethod::None => {
                // assume the endpoint is exactly as expected. This is not recommended unless server to server communication occurs
                // 1-1 mapping
                let socket = self.socket.take().ok_or_else(|| FirewallError::HolePunch("UDP socket not loaded".to_string()))?;
                let bind_addr = socket.local_addr()?;
                Ok(HolePunchedUdpSocket { socket, addr: HolePunchedSocketAddr { initial: self.peer_external_addr(), natted: self.peer_external_addr(), remote_internal_bind_addr: bind_addr } })
            }
        }
    }

    fn peer_external_addr(&self) -> SocketAddr {
        self.possible_endpoints[0].clone()
    }

    #[allow(dead_code)]
    fn peer_internal_addr(&self) -> Option<SocketAddr> {
        self.possible_endpoints.get(0).cloned()
    }

    pub async fn try_next(&mut self) -> Result<HolePunchedUdpSocket, FirewallError> {
        if !self.method3.0 {
            return self.try_method(NatTraversalMethod::Method3).await
        }

        if !self.upnp_handler.0 {
            return self.try_method( NatTraversalMethod::UPnP).await
        }

        Err(FirewallError::HolePunchExhausted)
    }

    /// returns None if all techniques have been exhausted
    pub fn get_next_method(&self) -> Option<NatTraversalMethod> {
        if !self.method3.0 {
            return Some(NatTraversalMethod::Method3)
        }

        if !self.upnp_handler.0 {
            return Some(NatTraversalMethod::UPnP)
        }

        None
    }

    pub fn get_bind_addr(&self) -> SocketAddr {
        self.local_bind_addr
    }

}

/// Methods described in https://thomaspbraun.com/pdfs/NAT_Traversal/NAT_Traversal.pdf
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MethodType {
    METHOD1, METHOD2, METHOD3, METHOD4, METHOD5
}
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RelativeNodeType {
    Initiator,
    Receiver
}

impl RelativeNodeType {
    pub fn into_byte(self) -> u8 {
        match self {
            RelativeNodeType::Initiator => 10,
            RelativeNodeType::Receiver => 20
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            10 => Some(RelativeNodeType::Initiator),
            20 => Some(RelativeNodeType::Receiver),
            _ => None
        }
    }
}

impl MethodType {
    pub fn into_byte(self) -> u8 {
        match self {
            MethodType::METHOD1 => 0,
            MethodType::METHOD2 => 1,
            MethodType::METHOD3 => 2,
            MethodType::METHOD4 => 3,
            MethodType::METHOD5 => 4
        }
    }

    pub fn for_value(input: usize) -> Option<Self> {
        match input {
            0 => Some(MethodType::METHOD1),
            1 => Some(MethodType::METHOD2),
            2 => Some(MethodType::METHOD3),
            3 => Some(MethodType::METHOD4),
            4 => Some(MethodType::METHOD5),
            _ => None
        }
    }
}

#[async_trait]
pub trait LinearUdpHolePunchImpl {
    /// Passes the outbound sender to the hole puncher. Supplied by hyxe_net.
    /// This should be ran on its own async task to not block
    ///
    /// Returns the first successful hole-punched UDP socket
    ///
    /// `endpoint`: is the initial send location
    /// `sockets`: Must be the same length as the base_local_ports
    async fn execute(&self, socket: &UdpSocket, endpoints: &Vec<SocketAddr>) -> Result<HolePunchedSocketAddr, FirewallError>;
}

pub mod nat_payloads {
    /// Sent by the initiator
    pub const SYN: &[u8] = b"SYN";
    pub const SYN_ACK: &[u8] = b"SYN_ACK";
    pub const ACK: &[u8] = b"ACK";
}
