use tokio::io::{BufReader, AsyncBufReadExt};
use hyxe_nat::udp_traversal::linear::RelativeNodeType;
use hyxe_nat::udp_traversal::synchronization_phase::UdpHolePuncher;
use hyxe_nat::quic::QuicEndpointType;

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

    let ref server_stream = tokio::net::TcpStream::connect("51.81.86.78:25025").await.unwrap();
    log::info!("Established TCP server connection");

    let hole_punched_socket = UdpHolePuncher::new(server_stream, RelativeNodeType::Initiator, Default::default()).await.unwrap();

    log::info!("Successfully hole-punched socket to peer @ {:?}", hole_punched_socket.addr);
    let (mut sink, mut stream) = hyxe_nat::quic::QuicContainer::new(hole_punched_socket, QuicEndpointType::client_dangerous_no_verify("mail.satorisocial.com")).await.unwrap().first_conn.take().unwrap();
    log::info!("Successfully obtained QUIC connection ...");

    let writer = async move {
        let mut stdin = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(input)) = stdin.next_line().await {
            log::info!("About to send: {}", &input);
            sink.write(input.as_bytes()).await.unwrap();
        }

        log::info!("writer ending");
    };

    let reader = async move {
        let input = &mut [0u8; 4096];
        loop {
            let len = stream.read(input).await.unwrap().unwrap();
            if let Ok(string) = String::from_utf8(Vec::from(&input[..len])) {
                log::info!("[Message]: {}", string);
            }
        }
    };

    tokio::select! {
        res0 = writer => res0,
        res1 = reader => res1
    }

        /*
    let writer = async move {
        let mut stdin = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(input)) = stdin.next_line().await {
            log::info!("About to send (bind:{:?}->{:?}): {}", hole_punched_socket.socket.local_addr().unwrap(), hole_punched_socket.addr.natted, &input);
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
    }*/

    log::info!("Quitting program clientside");
}