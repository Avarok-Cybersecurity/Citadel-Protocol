#![feature(async_closure)]

use tokio::net::UdpSocket;
use hyxe_nat::udp_traversal::linear::SingleUDPHolePuncher;
use std::net::SocketAddr;
use hyxe_nat::udp_traversal::NatTraversalMethod;
use byteorder::{NetworkEndian, ByteOrder, BigEndian};
use hyxe_nat::time_tracker::TimeTracker;
use tokio::time::Duration;
use hyxe_nat::local_firewall_handler::{open_local_firewall_port, FirewallProtocol, remove_firewall_rule, check_permissions};
use hyxe_nat::hypernode_type::HyperNodeType;
use hyxe_nat::nat_identification::NatType;

fn get_reuse_udp_socket(addr: &str, port: u16) -> UdpSocket {
    let mut build = net2::UdpBuilder::new_v4().unwrap();
    build.reuse_address(true).unwrap();
    let res = open_local_firewall_port(FirewallProtocol::UDP(port)).unwrap();
    if !res.status.success() {
        panic!("Unable to open firewall port. Reason: {}", unsafe { String::from_utf8_unchecked(res.stdout) });
    }

    UdpSocket::from_std(build.bind((addr, port)).unwrap()).unwrap()
}

fn ports_from_bytes<T: AsRef<[u8]>>(input: T) -> Vec<u16> {
    let input = input.as_ref();
    let port_count = input.len() / 2; // 2 bytes per u16
    let mut ret = Vec::with_capacity(port_count);

    for x in 0..port_count {
        let start = x*2;
        let end = start + 1;
        let port = NetworkEndian::read_u16(&input[start..=end]);
        ret.push(port);
    }

    ret
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
    const PORT_COUNT: usize = 1;
    const PORT_START: usize = 25000;
    const PORT_END: usize = PORT_START + PORT_COUNT;

    setup_log();
    check_permissions();

    let local_nat_type = NatType::identify().await.unwrap();
    log::info!("Nat Type: {:?}", local_nat_type);

    let tt = TimeTracker::new().await.unwrap();
    let mut tmp_socket = get_reuse_udp_socket("0.0.0.0", PORT_START as u16);
    let buf = &mut [0u8; 256];
    let (cnt, remote_socket) = tmp_socket.recv_from(buf).await.unwrap();
    log::info!("Received packet from {:?}", &remote_socket);
    let remote_ports = ports_from_bytes(&buf[..cnt-8]);
    let sync_time = BigEndian::read_i64(&buf[cnt-8..]);
    log::info!("Sync time: {}", sync_time);
    log::info!("Remote ports: {:?}", &remote_ports);

    std::mem::drop(tmp_socket);


    // For the exercise, we assume same the IP of the socket, and the same port range, but starting on the recv port
    //let remote_start_port = remote_socket.port();
    //let remote_end_port = remote_start_port + PORT_COUNT as u16;
    let mut endpoints = Vec::with_capacity(remote_ports.len());
    let mut local_sockets_mirrored = Vec::with_capacity(remote_ports.len());

    let fw_ports = local_sockets_mirrored.iter().map(|sck: &UdpSocket| FirewallProtocol::UDP(sck.local_addr().unwrap().port())).collect::<Vec<FirewallProtocol>>();

    for port in remote_ports {
        endpoints.push(SocketAddr::new(remote_socket.ip(), port as u16));
        local_sockets_mirrored.push(get_reuse_udp_socket("0.0.0.0", PORT_START as u16));
    }

    let delta = i64::abs(tt.get_global_time_ns() - sync_time);
    log::info!("Will wait for {} nanos", delta);
    tokio::task::spawn(tokio::time::delay_for(Duration::from_nanos(delta as u64))).await.unwrap();

    // We start right-away
    let mut hole_puncher = SingleUDPHolePuncher::new_receiver(HyperNodeType::GloballyReachable, Default::default(), NatType::Unknown);
    let hole_punched_socket = tokio::task::spawn((async move || { hole_puncher.try_method(&mut local_sockets_mirrored, &endpoints, NatTraversalMethod::Method3).await })()).await.unwrap().unwrap();
    log::info!("Server received hole-punched addr {:?}", hole_punched_socket.addr);

    for fw_port in fw_ports {
        let output = remove_firewall_rule(fw_port).unwrap();
        if !output.status.success() {
            panic!("Unable to remove firewall rule: {}", unsafe { String::from_utf8_unchecked(output.stdout) });
        }
    }
}