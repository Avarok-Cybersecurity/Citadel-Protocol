use tokio::io::{BufReader, AsyncBufReadExt};
use hyxe_nat::udp_traversal::linear::RelativeNodeType;
use hyxe_nat::udp_traversal::synchronization_phase::UdpHolePuncher;

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
    let listener = tokio::net::TcpListener::bind("0.0.0.0:25025").await.unwrap();

    let (ref client_stream, peer_addr) = listener.accept().await.unwrap();
    log::info!("Received client stream from {:?}", peer_addr);

    let ref hole_punched_socket = UdpHolePuncher::new(client_stream, RelativeNodeType::Receiver, Default::default()).await.unwrap();
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