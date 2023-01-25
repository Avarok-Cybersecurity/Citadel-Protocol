use crate::udp_traversal::HolePunchID;
use citadel_io::UdpSocket;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};

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
    pub socket: UdpSocket,
    pub addr: TargettedSocketAddr,
}

impl HolePunchedUdpSocket {
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
}
