use std::net::{SocketAddr, IpAddr};
use std::fmt::{Display, Formatter};
use tokio::net::UdpSocket;
use serde::{Serialize, Deserialize};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct HolePunchedSocketAddr {
    // Outbound packets should get sent here
    pub initial: SocketAddr,
    // Inbound packets coming from 'initial" will read as this address
    pub natted: SocketAddr
}

impl HolePunchedSocketAddr {
    pub fn new(initial: SocketAddr, natted: SocketAddr) -> Self {
        Self { initial, natted }
    }

    pub fn ip_translated(&self) -> bool {
        self.initial.ip() != self.natted.ip()
    }

    pub fn port_translated(&self) -> bool {
        self.initial.port() != self.natted.port()
    }

    pub fn eq_to(&self, ip_addr: IpAddr, port: u16) -> bool {
        (ip_addr == self.initial.ip() && port == self.initial.port()) ||
            (ip_addr == self.natted.ip() && port == self.natted.port())
    }

    pub fn recv_packet_valid(&self, recv_packet_socket: SocketAddr) -> bool {
        recv_packet_socket.ip() == self.natted.ip()
    }
}

impl Display for HolePunchedSocketAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "(Original, Natted): {:?} -> {:?}", &self.initial, &self.natted)
    }
}

#[derive(Debug)]
pub struct HolePunchedUdpSocket {
    pub socket: UdpSocket,
    pub addr: HolePunchedSocketAddr
}