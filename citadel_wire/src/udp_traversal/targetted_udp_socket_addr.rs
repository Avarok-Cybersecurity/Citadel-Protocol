use crate::udp_traversal::HolePunchID;
use citadel_io::UdpSocket;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TargettedSocketAddr {
    // Outbound packets should get sent here. Often, this will be equivalent to "receive_address"
    //, unless, UPnP is used
    pub send_address: SocketAddr,
    pub receive_address: SocketAddr,
    pub unique_id: HolePunchID,
}

impl TargettedSocketAddr {
    pub fn new(initial: SocketAddr, natted: SocketAddr, unique_id: HolePunchID) -> Self {
        Self {
            send_address: initial,
            receive_address: natted,
            unique_id,
        }
    }

    pub fn new_invariant(addr: SocketAddr) -> Self {
        Self {
            send_address: addr,
            receive_address: addr,
            unique_id: HolePunchID::new(),
        }
    }

    pub fn ip_translated(&self) -> bool {
        self.send_address.ip() != self.receive_address.ip()
    }

    pub fn port_translated(&self) -> bool {
        self.send_address.port() != self.receive_address.port()
    }

    pub fn eq_to(&self, ip_addr: IpAddr, port: u16) -> bool {
        (ip_addr == self.send_address.ip() && port == self.send_address.port())
            || (ip_addr == self.receive_address.ip() && port == self.receive_address.port())
    }

    pub fn recv_packet_valid(&self, recv_packet_socket: SocketAddr) -> bool {
        recv_packet_socket.ip() == self.receive_address.ip()
    }
}

impl Display for TargettedSocketAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "(Original, Natted): {:?} -> {:?}",
            &self.send_address, &self.receive_address
        )
    }
}

#[derive(Debug)]
pub struct HolePunchedUdpSocket {
    pub local_id: HolePunchID,
    pub(crate) socket: UdpSocket,
    pub addr: TargettedSocketAddr,
}

impl HolePunchedUdpSocket {
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        let bind_addr = self.socket.local_addr()?;
        let bind_ip = bind_addr.ip();
        let send_ip = self.addr.send_address.ip();
        let send_ip = match (bind_ip, send_ip) {
            (IpAddr::V4(_bind_ip), IpAddr::V6(send_ip)) => {
                // If we're sending from an IPv4 address to an IPv6 address, we need to convert the
                // IPv4 address to an IPv4-mapped IPv6 address
                if let Some(addr) = send_ip.to_ipv4_mapped() {
                    IpAddr::V4(addr)
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "IPv4-mapped IPv6 address conversion failed; Cannot send from ipv4 socket to v6",
                    ));
                }
            }

            (IpAddr::V6(_bind_ip), IpAddr::V4(send_ip)) => {
                // If we're sending from an IPv6 address to an IPv4 address, we need to convert the
                // IPv4 address to an IPv4-mapped IPv6 address
                IpAddr::V6(send_ip.to_ipv6_mapped())
            }

            _ => send_ip,
        };

        let target_addr = SocketAddr::new(send_ip, addr.port());
        log::trace!(target: "citadel", "Sending packet from {bind_addr} to {target_addr}");

        tokio::time::timeout(
            Duration::from_secs(2),
            self.socket.send_to(buf, target_addr),
        )
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::TimedOut, err.to_string()))?
    }
    // After hole-punching, some packets may be sent that need to be flushed
    // this cleanses the stream
    pub(crate) fn cleanse(&self) -> std::io::Result<()> {
        let buf = &mut [0u8; 4096];
        loop {
            match self.socket.try_recv(buf) {
                Ok(_) => {
                    continue;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}
