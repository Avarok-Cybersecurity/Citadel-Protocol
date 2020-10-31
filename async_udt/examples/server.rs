use std::net::UdpSocket;
use async_udt::async_udt_socket::UdtSocket;
use udt::{SocketFamily, SocketType};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let std_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let server_addr = std_socket.local_addr().unwrap();
    let mut udt_socket_server = UdtSocket::new(SocketFamily::AFInet, SocketType::Datagram, std_socket);
    println!("Starting server ...");
    Ok(())
}