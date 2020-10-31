use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant};
use std::net::IpAddr;
use std::str::FromStr;
use igd::PortMappingProtocol;
use hyxe_nat::upnp_handler::UPnPHandler;
use hyxe_nat::time_tracker::TimeTracker;
use bytes::buf::BufMutExt;
use std::io::Write;
use byteorder::{WriteBytesExt, NetworkEndian};
use bytes::BufMut;

const PORT: u16 = 25000;
#[tokio::main]
async fn main() {
    let tt = TimeTracker::new().await.unwrap();
    let bind_addr = IpAddr::from_str("0.0.0.0").unwrap();
    let target = IpAddr::from_str("178.128.128.105").unwrap();

    let mut udp_socket = UdpSocket::bind((bind_addr.clone(), PORT)).await.unwrap();

    println!("Socket bound to 0.0.0.0:25000! Node is client; attempting connection to {}:25000", target);
    udp_socket.set_ttl(2).unwrap();

    let sync_start_time = tt.get_global_time_ns() + 500_000_000;
    let sync_start_time_inst = Instant::now() + Duration::from_millis(3000);

    let mut msg = Vec::with_capacity(3+8);
    msg.put(b"SYN" as &[u8]);
    msg.put_i64(sync_start_time);
    let msg = msg.as_slice();
    println!("Sending message w/{} bytes", msg.len());

    udp_socket.send_to(msg, (target.clone(), PORT)).await.unwrap();
    println!("Sent message; now waiting for sync time...");
    let recv_buffer= &mut [0u8; 3000];
    tokio::task::spawn(tokio::time::delay_until(sync_start_time_inst)).await.unwrap();

    println!("Sending short acks...");
    for x in 0..20 {
        // send short acks
        udp_socket.send_to(b"SYN", (target.clone(), PORT)).await.unwrap();
        //println!("{}", x);
        tokio::time::delay_for(Duration::from_millis(20)).await;
    }

    println!("Sending long ACKs ...");

    // now send long acks
    udp_socket.set_ttl(255).unwrap();
    for x in 0..20 {
        // send short acks
        udp_socket.send_to(b"SYN", (target.clone(), PORT)).await.unwrap();
        tokio::time::delay_for(Duration::from_millis(20)).await;
    }

    println!("Awaiting packet ...");
    let (amt, addr_from) = udp_socket.recv_from(recv_buffer).await.unwrap();
    let data = &recv_buffer[0..amt];
    println!("Received response from server ({} bytes) {:?}: {}", amt, addr_from, unsafe { String::from_utf8_unchecked(data.to_vec()) });
}