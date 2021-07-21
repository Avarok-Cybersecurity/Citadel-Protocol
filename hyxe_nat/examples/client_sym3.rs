use hyxe_nat::nat_identification::NatType;
use tokio::io::{AsyncWriteExt, AsyncReadExt, BufReader, AsyncBufReadExt};
use serde::{Serialize, Deserialize};
use hyxe_nat::time_tracker::TimeTracker;
use std::time::Duration;
use hyxe_nat::udp_traversal::linear::LinearUDPHolePuncher;
use hyxe_nat::udp_traversal::NatTraversalMethod;
use tokio::net::UdpSocket;

#[derive(Serialize, Deserialize)]
struct Transfer {
    nat_type: NatType,
    sync_time: Option<i64>
}

fn setup_log() {
    std::env::set_var("RUST_LOG", "error,warn,info,trace");
    //std::env::set_var("RUST_LOG", "error");
    let _ = env_logger::try_init();
    log::trace!("TRACE enabled");
    log::info!("INFO enabled");
    log::warn!("WARN enabled");
    log::error!("ERROR enabled");
}

#[tokio::main]
async fn main() {
    setup_log();
    let nat_type = NatType::identify().await.unwrap();
    let tt = TimeTracker::new();
    log::info!("Local NAT type: {:?}", &nat_type);
    let mut server_stream = tokio::net::TcpStream::connect("51.81.86.78:25025").await.unwrap();
    let udp_sck = UdpSocket::bind("0.0.0.0:25025").await.unwrap();
    log::info!("Established TCP server connection");
    let buf = &mut [0u8; 4096];
    // we get the server's data
    let len = server_stream.read(buf).await.unwrap();
    let server_transfer: Transfer = bincode2::deserialize(&buf[..len]).unwrap();
    log::info!("Server's NAT type: {:?}", &server_transfer.nat_type);
    let delay_ns = 1_000_000_000;
    let sync_time = tt.get_global_time_ns() + delay_ns; // 1 second from now
    server_stream.write_all(&bincode2::serialize(&Transfer { nat_type: nat_type.clone(), sync_time: Some(sync_time) }).unwrap()).await.unwrap();

    let predicted_endpoint = server_transfer.nat_type.predict_external_addr_from_local_bind_port(25025).unwrap();
    log::info!("Predicted server endpoint: {:?}", predicted_endpoint);
    let mut sockets = vec![udp_sck];
    let endpoints = vec![predicted_endpoint];

    // wait for synchronization
    tokio::time::sleep(Duration::from_nanos(delay_ns as _)).await;

    // setup hole punching
    let mut hole_puncher = LinearUDPHolePuncher::new_initiator(nat_type, Default::default(), server_transfer.nat_type);
    let ref hole_punched_socket = hole_puncher.try_method(&mut sockets, &endpoints, NatTraversalMethod::Method3).await.unwrap();

    log::info!("Successfully hole-punched socket to peer @ {:?}", hole_punched_socket.addr);

    let writer = async move {
        let mut stdin = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(input)) = stdin.next_line().await {
            log::info!("About to send: {}", &input);
            hole_punched_socket.socket.send_to(input.as_bytes(), hole_punched_socket.addr.natted).await.unwrap();
        }
    };

    let reader = async move {
        let input = &mut [0u8; 4096];
        let len = hole_punched_socket.socket.recv(input).await.unwrap();
        let string = String::from_utf8(Vec::from(&input[..len])).unwrap();
        log::info!("[Message]: {}", string);
    };

    tokio::select! {
            res0 = writer => res0,
            res1 = reader => res1
    }

    log::info!("Quitting program clientside");
}