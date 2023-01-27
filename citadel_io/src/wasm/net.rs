use std::fmt::Debug;

pub type TcpStream = tokio::net::TcpStream;
pub type UdpSocket = UdpSocketImpl;
pub type TcpListener = tokio::net::TcpListener;

#[derive(Debug)]
pub struct UdpSocketImpl;
