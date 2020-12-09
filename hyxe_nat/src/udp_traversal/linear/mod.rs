use async_trait::async_trait;
use std::net::{SocketAddr, IpAddr};
use crate::error::FirewallError;
use crate::udp_traversal::linear::method3::Method3;
use crate::udp_traversal::hole_punched_udp_socket_addr::HolePunchedSocketAddr;
use tokio::net::UdpSocket;
use crate::udp_traversal::NatTraversalMethod;
use crate::upnp_handler::UPnPHandler;
use tokio::time::Duration;
use igd::PortMappingProtocol;
use crate::local_firewall_handler::{open_local_firewall_port, FirewallProtocol};
use crate::hypernode_type::HyperNodeType;
use crate::udp_traversal::linear::method3_encrypted::Method3Encrypted;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use std::sync::Arc;

pub mod encrypted_config_container;

pub mod method1;
pub mod method3;
pub mod method3_encrypted;

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
pub struct LinearUDPHolePuncher {
    method3: (bool, Method3),
    encrypted_method3: (bool, Option<Method3Encrypted>),
    upnp_handler: (bool, Option<UPnPHandler>),
    local_hypernode_type: HyperNodeType
}

impl LinearUDPHolePuncher {

    /// This assumes STUN has already been used. In the case of HYXE networks, since the central server
    /// proxies information anyways, the holes will only need to be punched when the central server needs
    /// to communicate with the client through UDP. Client to server UDP works almost guaranteed, but not
    /// the other way around in the case with carrier grade or symmetric NATs.
    pub fn new_initiator(local_hypernode_type: HyperNodeType, encrypted_config_container: Option<EncryptedConfigContainer>) -> Self {
        Self::new(RelativeNodeType::Initiator, local_hypernode_type, encrypted_config_container)
    }

    pub fn new_receiver(local_hypernode_type: HyperNodeType, encrypted_config_container: Option<EncryptedConfigContainer>) -> Self {
        Self::new(RelativeNodeType::Receiver, local_hypernode_type, encrypted_config_container)
    }

    fn new(relative_node_type: RelativeNodeType, local_hypernode_type: HyperNodeType, encrypted_config_container: Option<EncryptedConfigContainer>) -> Self {
        let method3= Method3::new(relative_node_type);
        let mut method3_encrypted = None;
        if let Some(encrypted_config_container) = encrypted_config_container {
            let encrypted_config_container = Arc::new(encrypted_config_container);
            method3_encrypted = Some(Method3Encrypted::new(relative_node_type, encrypted_config_container));
        }

        Self { method3: (false, method3), encrypted_method3: (false, method3_encrypted), upnp_handler: (false, None), local_hypernode_type }
    }


    /// During pre-connect stage 0 (initiator) AND stage 1 (receiver), this should be called to share the socket information
    /// with the other side. This is preferred, as it also configures the local firewall to allow all inbound/outbound traffic
    /// on these ports
    pub fn reserve_new_udp_sockets<T: Into<IpAddr>>(count: usize, bind_addr: T) -> Result<Vec<UdpSocket>, FirewallError> {
        let bind_addr = bind_addr.into();
        let result = (0..count).into_iter().map(|_| -> Result<UdpSocket, std::io::Error> {
            let socket = std::net::UdpSocket::bind(SocketAddr::new(bind_addr, 0))?;
            // on android, the below will fail since sudo access is not permissible
            if let Err(err) = open_local_firewall_port(FirewallProtocol::UDP(socket.local_addr()?.port())) {
                log::warn!("Unable to ensure UDP ports were opened. Packets may not traverse ({})", err.to_string());
            }
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
    }

    //
    pub async fn try_method(&mut self, sockets: &mut Vec<UdpSocket>, endpoints: &Vec<SocketAddr>, method: NatTraversalMethod) -> Result<Vec<HolePunchedSocketAddr>, FirewallError> {
        debug_assert_eq!(sockets.len(), endpoints.len());

        match method {
            NatTraversalMethod::UPnP => {
                self.upnp_handler.0 = true;

                if self.local_hypernode_type != HyperNodeType::BehindResidentialNAT {
                    return Err(FirewallError::NotApplicable)
                }

                if self.upnp_handler.1.is_none() {
                    self.upnp_handler.1 = Some(UPnPHandler::new(Some(Duration::from_millis(2000))).await?);
                }

                let handler = self.upnp_handler.1.as_ref().unwrap();
                let mut ret = Vec::with_capacity(endpoints.len());
                for (local_socket, adjacent_endpoint) in sockets.into_iter().zip(endpoints.iter()) {
                    let reserved_port = handler.open_any_firewall_port(PortMappingProtocol::UDP, None, "SatoriNET", None, local_socket.local_addr()?.port()).await?;
                    let initial_socket = adjacent_endpoint.clone();
                    // The return address will appear as the natted socket below because the adjacent endpoint must send through the reserve port
                    let natted_socket = SocketAddr::new(adjacent_endpoint.ip(), reserved_port);
                    println!("[UPnP]: Opened port {}", reserved_port);
                    let hole_punched_socket = HolePunchedSocketAddr::new(initial_socket, natted_socket);
                    println!("[UPnP] {}", &hole_punched_socket);
                    ret.push(hole_punched_socket);
                }

                Ok(ret)
            },

            NatTraversalMethod::Method3 => {
                self.method3.0 = true;
                self.method3.1.execute(sockets, endpoints).await
            },

            NatTraversalMethod::None => {
                // assume the endpoint is exactly as expected. This is not recommended unless server to server communication occurs
                // 1-1 mapping
                Ok(endpoints.into_iter().map(|remote_addr| {
                    HolePunchedSocketAddr::new(remote_addr.clone(), *remote_addr)
                }).collect::<Vec<HolePunchedSocketAddr>>())
            }
        }
    }

    pub async fn try_next(&mut self, sockets: &mut Vec<UdpSocket>, endpoints: &Vec<SocketAddr>) -> Result<Vec<HolePunchedSocketAddr>, FirewallError> {
        if !self.method3.0 {
            return self.try_method(sockets, endpoints, NatTraversalMethod::Method3).await
        }

        if !self.upnp_handler.0 {
            return self.try_method(sockets, endpoints, NatTraversalMethod::UPnP).await
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
    /// Returns the NAT ports which this node can send packets to. (nat_ip, nat_port[..])
    ///
    /// `endpoint`: is the initial send location
    /// `sockets`: Must be the same length as the base_local_ports
    async fn execute(&self, sockets: &mut Vec<UdpSocket>, endpoints: &Vec<SocketAddr>) -> Result<Vec<HolePunchedSocketAddr>, FirewallError>;
}

pub mod nat_payloads {
    /// Sent by the initiator
    pub const SYN: &[u8] = b"SYN";
    pub const SYN_ACK: &[u8] = b"SYN_ACK";
    pub const ACK: &[u8] = b"ACK";
}
