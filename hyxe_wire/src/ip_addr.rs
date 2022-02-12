use std::net::{IpAddr, SocketAddr};

use tokio::net::UdpSocket;
use std::str::FromStr;

const LOCAL_BIND_ADDR: &str = "0.0.0.0:0";
const GOOGLE_DNS: &str = "8.8.8.8:80";
/// get the local ip address
pub async fn get_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind(SocketAddr::from_str(LOCAL_BIND_ADDR).unwrap()).await.ok()?;
    socket.connect(SocketAddr::from_str(GOOGLE_DNS).unwrap()).await.ok()?;
    Some(socket.local_addr().ok()?.ip())
}