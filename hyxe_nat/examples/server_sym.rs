use tokio::net::UdpSocket;
use std::net::{SocketAddr, IpAddr};
use std::str::FromStr;
use tokio::time::Duration;
use hyxe_nat::time_tracker::TimeTracker;
use byteorder::{NetworkEndian, ByteOrder};

const PORT: u16 = 25000;
#[tokio::main]
async fn main() {
    let tt = TimeTracker::new().await.unwrap();
    let mut udp_socket = UdpSocket::bind((IpAddr::from_str("0.0.0.0").unwrap(), PORT)).await.unwrap();
    let buf = &mut [0u8; 150];
    let (amt, peer_addr) = udp_socket.recv_from(buf).await.unwrap();
    println!("Received {} bytes from {}", amt, &peer_addr);
    let data = &buf[..amt];
    let (syn, sync_start_time) = data.split_at(3);
    let sync_start_time = NetworkEndian::read_i64(sync_start_time);
    let delta = sync_start_time - tt.get_global_time_ns();
    let sync_start_time = Duration::from_nanos(delta as u64);

    tokio::time::delay_for(sync_start_time).await;
    udp_socket.set_ttl(2).unwrap();
    println!("Sending short acks");
    for x in 0..20 {
        // send short acks
        let data = format!("SYN_ACKS{}",x);
        udp_socket.send_to(data.as_str().as_bytes(), peer_addr.clone()).await.unwrap();
        tokio::time::delay_for(Duration::from_millis(20)).await;
    }

    println!("Sending long acks");
    // now send long acks
    udp_socket.set_ttl(255).unwrap();
    for x in 0..20 {
        // send short acks
        let data = format!("SYN_ACKL{}", x);
        udp_socket.send_to(data.as_str().as_bytes(), peer_addr.clone()).await.unwrap();
        tokio::time::delay_for(Duration::from_millis(20)).await;
    }
}