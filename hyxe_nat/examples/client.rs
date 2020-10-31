use tokio::net::UdpSocket;
use tokio::time::Duration;
use std::net::IpAddr;
use std::str::FromStr;
use igd::PortMappingProtocol;
use hyxe_nat::upnp_handler::UPnPHandler;

const PORT: u16 = 25000;
#[tokio::main]
async fn main() {
    let bind_addr = IpAddr::from_str("0.0.0.0").unwrap();

    let firewall_handler = UPnPHandler::new(Some(Duration::from_millis(3000))).await.unwrap();

    println!(": {}", &firewall_handler);
    let pub_ip = match firewall_handler.get_external_ip().await {
        Ok(ip) => ip,
        Err(err) => return println!("Failed to get external IP: {:?}", err),
    };

    println!("Public IP:{}", pub_ip);
    let target = IpAddr::from_str("178.128.128.105").unwrap();
    let mut send_port = 0;
    for port in PORT..25001 {
        match firewall_handler.open_firewall_port(PortMappingProtocol::UDP, Some(50),"hyxewave", None,PORT, PORT).await {
            Ok(_) => {
                println!("Successfully obtained port {} through the firewall!", PORT);
                send_port = PORT;
            },

            Err(err) => {
                println!("{:?}", err);
            }
        }
    }



    let mut udp_socket = UdpSocket::bind((bind_addr.clone(), PORT)).await.unwrap();
    println!("Socket bound to 0.0.0.0:25000! Node is client; attempting connection to {}:25000", target);
    udp_socket.send_to(&send_port.to_be_bytes(), (target.clone(), PORT)).await.unwrap();
    let recv_buffer= &mut [0u8; 128];

    let (amt, addr_from) = udp_socket.recv_from(recv_buffer).await.unwrap();
    let data = &recv_buffer[0..amt];
    println!("Received response from server ({} bytes) {:?}: {}", amt, addr_from, unsafe { String::from_utf8_unchecked(data.to_vec()) });
}