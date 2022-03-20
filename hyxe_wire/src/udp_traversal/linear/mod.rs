use std::net::SocketAddr;

use async_trait::async_trait;
use either::Either;
use igd::PortMappingProtocol;
use tokio::net::UdpSocket;
use tokio::time::Duration;

use crate::error::FirewallError;
use crate::udp_traversal::{HolePunchID, NatTraversalMethod};
use crate::udp_traversal::targetted_udp_socket_addr::{TargettedSocketAddr, HolePunchedUdpSocket};
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::udp_traversal::linear::method3::Method3;
use crate::upnp_handler::UPnPHandler;
use netbeam::sync::RelativeNodeType;

pub mod encrypted_config_container;

pub mod method1;
pub mod method3;

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
    unique_id: HolePunchID
}

impl SingleUDPHolePuncher {
    pub fn new(relative_node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer, local_socket: UdpSocket, peer_addrs_to_ping: Vec<SocketAddr>) -> Result<Self, anyhow::Error> {
        let local_bind_addr = local_socket.local_addr()?;
        let unique_id = HolePunchID::new();
        log::info!("Setting up single-udp hole-puncher. Local bind addr: {:?} | Peer Addrs to ping: {:?} | [id = {:?}]", local_bind_addr, peer_addrs_to_ping, unique_id);

        let method3= Method3::new(relative_node_type, encrypted_config_container, unique_id.clone());

        Ok(Self { method3: (false, method3), upnp_handler: (false, None), socket: Some(local_socket), possible_endpoints: peer_addrs_to_ping, relative_node_type, unique_id })
    }

    pub fn take_socket(&mut self) -> Option<UdpSocket> {
        self.socket.take()
    }

    /// kill_switch: Item sent is (local_id, peer_id)
    pub async fn try_method(&mut self, method: NatTraversalMethod, mut kill_switch: tokio::sync::broadcast::Receiver<(HolePunchID, HolePunchID)>, post_kill_rebuild: tokio::sync::mpsc::UnboundedSender<Option<HolePunchedUdpSocket>>) -> Result<HolePunchedUdpSocket, FirewallError> {
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
                let unique_id = self.unique_id;
                let hole_punched_addr = TargettedSocketAddr::new(peer_external_addr, natted_socket, unique_id);
                log::info!("[UPnP] {}", &hole_punched_addr);

                Ok(HolePunchedUdpSocket { addr: hole_punched_addr, socket: self.socket.take().ok_or_else(|| FirewallError::HolePunch("UDP socket not loaded".to_string()))? })
            },

            NatTraversalMethod::Method3 => {
                self.method3.0 = true;
                let this_local_id = self.unique_id;

                let this = &*self;
                let process = async move {
                    this.method3.1.execute(this.socket.as_ref().ok_or_else(|| FirewallError::HolePunch("UDP socket not loaded".to_string()))?, &this.possible_endpoints).await
                };

                let kill_listener = async move {
                    if let Ok((local_id, peer_id)) = kill_switch.recv().await {
                        log::info!("[Kill Listener] Received signal. {:?} must == {:?} || {:?}", local_id, this_local_id, peer_id);
                        if local_id == this_local_id {
                            if this.has_remote_id_synd(peer_id) {
                                return Some((local_id, peer_id))
                            }
                        }
                    }

                    None
                };

                let res = tokio::select! {
                    res0 = process => Either::Right(res0?),
                    res1 = kill_listener => Either::Left(res1)
                };

                match res {
                    Either::Right(addr) => {
                        Ok(HolePunchedUdpSocket { socket: self.socket.take().unwrap(), addr })
                    }

                    Either::Left(id_opt) => {
                        match id_opt {
                            Some((_local_id, peer_id)) => {
                                post_kill_rebuild.send(Some(self.recovery_mode_generate_socket_by_remote_id(peer_id).ok_or_else(|| FirewallError::HolePunch("Kill switch called, but no matching values were found internally".to_string()))?)).map_err(|err| FirewallError::HolePunch(err.to_string()))?;
                            }

                            None => {
                                log::info!("Will end hole puncher {:?} since kill switch called", self.get_unique_id());
                                post_kill_rebuild.send(None).map_err(|err| FirewallError::HolePunch(err.to_string()))?;
                            }
                        }

                        Err(FirewallError::Skip)
                    }
                }
            },

            NatTraversalMethod::None => {
                // assume the endpoint is exactly as expected. This is not recommended unless server to server communication occurs
                // 1-1 mapping
                let socket = self.socket.take().ok_or_else(|| FirewallError::HolePunch("UDP socket not loaded".to_string()))?;
                //let bind_addr = socket.local_addr()?;
                let unique_id = self.unique_id;
                Ok(HolePunchedUdpSocket { socket, addr: TargettedSocketAddr { send_address: self.peer_external_addr(), receive_address: self.peer_external_addr(), unique_id } })
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

    pub fn get_unique_id(&self) -> HolePunchID {
        self.unique_id
    }

    /// this should only be called when the adjacent node verified that the connection occured
    pub fn recovery_mode_generate_socket_by_remote_id(&mut self, remote_id: HolePunchID) -> Option<HolePunchedUdpSocket> {
        let addr = self.method3.1.get_peer_external_addr_from_peer_hole_punch_id(remote_id)?;
        let socket = self.socket.take()?;
        Some(HolePunchedUdpSocket { addr, socket })
    }

    fn has_remote_id_synd(&self, remote_id: HolePunchID) -> bool {
        self.method3.1.get_peer_external_addr_from_peer_hole_punch_id(remote_id).is_some()
    }

    /// this should only be called when the adjacent node verified that the connection occured
    pub fn recovery_mode_generate_socket_by_addr(&mut self, addr: TargettedSocketAddr) -> Option<HolePunchedUdpSocket> {
        let socket = self.socket.take()?;
        Some(HolePunchedUdpSocket { addr, socket })
    }
}

/// Methods described in https://thomaspbraun.com/pdfs/NAT_Traversal/NAT_Traversal.pdf
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MethodType {
    METHOD1, METHOD2, METHOD3, METHOD4, METHOD5
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
    async fn execute(&self, socket: &UdpSocket, endpoints: &Vec<SocketAddr>) -> Result<TargettedSocketAddr, FirewallError>;
    /// used during "recovery mode" (when one side completes, but the other does not
    fn get_peer_external_addr_from_peer_hole_punch_id(&self, id: HolePunchID) -> Option<TargettedSocketAddr>;
    fn get_all_received_peer_hole_punched_ids(&self) -> Vec<HolePunchID>;
}

pub mod nat_payloads {
    /// Sent by the initiator
    pub const SYN: &[u8] = b"SYN";
    pub const SYN_ACK: &[u8] = b"SYN_ACK";
    pub const ACK: &[u8] = b"ACK";
}
