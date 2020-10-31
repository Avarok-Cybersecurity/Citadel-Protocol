use tokio::net::UdpSocket;
use std::net::{SocketAddr, IpAddr};
use std::str::FromStr;

const PORT: u16 = 25000;
#[tokio::main]
async fn main() {
    let mut sock = UdpSocket::bind((IpAddr::from_str("0.0.0.0").unwrap(), PORT)).await.unwrap();
    let buf = &mut [0u8; 150];
    let (amt, peer_addr) = sock.recv_from(buf).await.unwrap();
    println!("Received {} bytes from {}", amt, &peer_addr);
    let data = &buf[0..amt];
    let mut input: [u8; 2] = [0u8; 2];
    input[0] = data[0];
    input[1] = data[1];

    let valid_port = u16::from_be_bytes(input);
    println!("Received valid port: {}", valid_port);
    let remote_addr = SocketAddr::new(peer_addr.ip(), valid_port);
    sock.send_to(b"Hello from server!", remote_addr).await.unwrap();
}