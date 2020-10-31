use tokio::net::UdpSocket;
use std::net::{SocketAddr, IpAddr};
use std::str::FromStr;
use hyxe_nat::udp_traversal::linear::LinearUDPHolePuncher;
use hyxe_nat::udp_traversal::NatTraversalMethod;
use tokio::time::Duration;
use bytes::buf::BufMutExt;
use byteorder::{WriteBytesExt, BigEndian};
use hyxe_nat::time_tracker::TimeTracker;
use hyxe_nat::local_firewall_handler::{open_local_firewall_port, FirewallProtocol, remove_firewall_rule, check_permissions};
use hyxe_nat::hypernode_type::HyperNodeType;

fn get_reuse_udp_socket(addr: &str, port: u16) -> UdpSocket {
    let mut build = net2::UdpBuilder::new_v4().unwrap();
    build.reuse_address(true).unwrap();
    let res = open_local_firewall_port(FirewallProtocol::UDP(port)).unwrap();
    /*if !res.status.success() {
        panic!("Unable to open firewall port. Reason: {}", unsafe { String::from_utf8_unchecked(res.stdout) });
    }*/

    UdpSocket::from_std(build.bind((addr, port)).unwrap()).unwrap()
}

fn get_rand_socket() -> UdpSocket {
    let mut build = net2::UdpBuilder::new_v4().unwrap();
    build.reuse_address(true).unwrap();

    let sck = UdpSocket::from_std(build.bind("0.0.0.0:25001").unwrap()).unwrap();
    let port = sck.local_addr().unwrap().port();
    let res = open_local_firewall_port(FirewallProtocol::UDP(port)).unwrap();
    /*if !res.status.success() {
        panic!("Unable to open firewall port. Reason: {}", unsafe { String::from_utf8_unchecked(res.stdout) });
    }*/

    sck
}

fn setup_log() {
    std::env::set_var("RUST_LOG", "hyxe_nat=info,error,warn");
    env_logger::init();
    log::trace!("TRACE enabled");
    log::info!("INFO enabled");
    log::warn!("WARN enabled");
    log::error!("ERROR enabled");
}

#[tokio::main]
async fn main() {
    // remote
    const PORT_COUNT: u16 = 1;
    const START_PORT: u16 = 25000;
    const END_PORT: u16 = START_PORT + PORT_COUNT;

    setup_log();
    check_permissions();

    let target_addr = IpAddr::from_str("178.128.128.105").unwrap();
    let mut endpoints = (START_PORT..END_PORT).into_iter().map(|expected_remote_port| SocketAddr::new(target_addr, expected_remote_port)).collect::<Vec<SocketAddr>>();

    let mut sockets = (0..PORT_COUNT).into_iter().map(|_| get_rand_socket()).collect::<Vec<UdpSocket>>();
    let local_ports = sockets.iter().map(|sck| sck.local_addr().unwrap().port()).collect::<Vec<u16>>();

    let fw_ports = local_ports.iter().map(|port| FirewallProtocol::UDP(*port)).collect::<Vec<FirewallProtocol>>();

    let mut message = Vec::<u8>::with_capacity((local_ports.len()*2) + 8).writer();
    for val in local_ports {
        println!("Reserved local sck: 0.0.0.0:{}", val);
        message.write_u16::<BigEndian>(val).unwrap();
    }

    let tt = TimeTracker::new().await.unwrap();
    let sync_time_ns = tt.get_global_time_ns() + 1_000_000_000;
    message.write_i64::<BigEndian>(sync_time_ns).unwrap();
    println!("Sync time: {}", sync_time_ns);

    let message = message.into_inner();

    // send initial message to get the other end ready
    sockets[0].send_to(message.as_slice(), endpoints[0]).await.unwrap();

    // wait 200ms
    tokio::time::delay_for(Duration::from_millis(1000)).await;
    println!("Beginning hole-punching process ...");
    let mut hole_puncher = LinearUDPHolePuncher::new_initiator(HyperNodeType::BehindResidentialNAT);
    let hole_punched_sockets = hole_puncher.try_method(&mut sockets, &endpoints, NatTraversalMethod::Method3).await.unwrap();
    println!("Hole punching complete!");
    for hole_punched_addr in hole_punched_sockets {
        println!("{}", hole_punched_addr);
    }

    for fw_port in fw_ports {
        let output = remove_firewall_rule(fw_port).unwrap();
        if !output.status.success() {
            //panic!("Unable to remove firewall rule: {}", unsafe { String::from_utf8_unchecked(output.stdout) });
        }
    }
}