use hyxe_nat::nat_identification::NatType;
use tokio::io::{AsyncWriteExt, AsyncReadExt, BufReader, AsyncBufReadExt};
use serde::{Serialize, Deserialize};
use hyxe_nat::time_tracker::TimeTracker;
use std::time::Duration;
use hyxe_nat::udp_traversal::linear::LinearUDPHolePuncher;
use hyxe_nat::udp_traversal::NatTraversalMethod;
use std::net::{SocketAddr, IpAddr};

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
    let internal_addr = SocketAddr::new(nat_type.internal_ip().unwrap(), 25025);
    log::info!("Local NAT type: {:?}", &nat_type);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:25025").await.unwrap();
    let tt = TimeTracker::new();
    loop {
        let (mut client_stream, peer_addr) = listener.accept().await.unwrap();
        log::info!("Received client stream from {:?}", peer_addr);
        let buf = &mut [0u8; 4096];
        client_stream.write_all(&bincode2::serialize(&Transfer { nat_type: nat_type.clone(), sync_time: None }).unwrap()).await.unwrap();
        // receive the client's nat info
        let len = client_stream.read(buf).await.unwrap();
        let client_transfer: Transfer = bincode2::deserialize(&buf[..len]).unwrap();
        log::info!("Client NAT type: {:?}", &client_transfer.nat_type);
        // To connect to their UDP socket, first determine location
        let connect_addr = client_transfer.nat_type.predict_external_addr_from_local_bind_port(25025).unwrap();
        log::info!("Predicted peer port: {:?}", connect_addr);


        // now sleep to synchronize
        let delta = i64::abs(tt.get_global_time_ns() - client_transfer.sync_time.unwrap());
        log::info!("Will wait for {} nanos", delta);
        tokio::time::sleep(Duration::from_nanos(delta as u64)).await;

        // begin hole-punching subroutine
        log::info!("Executing serverside hole-punching subroutine");

        let mut hole_puncher = LinearUDPHolePuncher::new_receiver(nat_type.clone(), Default::default(), client_transfer.nat_type, SocketAddr::new(IpAddr::from([0,0,0,0]), 25025), connect_addr, internal_addr).unwrap();
        let ref hole_punched_socket = hole_puncher.try_method(NatTraversalMethod::Method3).await.unwrap();

        log::info!("Successfully hole-punched socket to peer @ {:?}", hole_punched_socket.addr);

        let writer = async move {
            let mut stdin = BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(input)) = stdin.next_line().await {
                log::info!("About to send: {}", &input);
                hole_punched_socket.socket.send_to(input.as_bytes(), hole_punched_socket.addr.natted).await.unwrap();
            }

            log::info!("writer ending");
        };

        let reader = async move {
            let input = &mut [0u8; 4096];
            loop {
                let len = hole_punched_socket.socket.recv(input).await.unwrap();
                if let Ok(string) = String::from_utf8(Vec::from(&input[..len])) {
                    log::info!("[Message]: {}", string);
                }
            }
        };

        tokio::select! {
            res0 = writer => res0,
            res1 = reader => res1
        }

        log::info!("Quitting program serverside");
    }
}