use tokio::io::{BufReader, AsyncBufReadExt};
use hyxe_wire::udp_traversal::udp_hole_puncher::UdpHolePuncher;
use hyxe_wire::quic::QuicEndpointListener;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::RelativeNodeType;

fn setup_log() {
    std::env::set_var("RUST_LOG", "lusna=trace");
    //std::env::set_var("RUST_LOG", "error");
    let _ = env_logger::try_init();
    log::trace!(target: "lusna", "TRACE enabled");
    log::trace!(target: "lusna", "INFO enabled");
    log::warn!(target: "lusna", "WARN enabled");
    log::error!(target: "lusna", "ERROR enabled");
}

#[tokio::main]
async fn main() {
    setup_log();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:25025").await.unwrap();
    let (client_stream, peer_addr) = listener.accept().await.unwrap();
    log::trace!(target: "lusna", "Received client stream from {:?}", peer_addr);

    let hole_punched_socket = UdpHolePuncher::new(&NetworkEndpoint::register(RelativeNodeType::Receiver, client_stream).await.unwrap(), Default::default()).await.unwrap();
    log::trace!(target: "lusna", "Successfully hole-punched socket to peer @ {:?}", hole_punched_socket.addr);

    let (_conn, mut sink, mut stream) = hyxe_wire::quic::QuicServer::new_from_pkcs_12_der_path(hole_punched_socket.socket, "../keys/testing.p12", "mrmoney10").unwrap().next_connection().await.unwrap();
    log::trace!(target: "lusna", "Successfully obtained QUIC connection ...");

    let writer = async move {
        let mut stdin = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(input)) = stdin.next_line().await {
            log::trace!(target: "lusna", "About to send: {}", &input);
            sink.write(input.as_bytes()).await.unwrap();
        }

        log::trace!(target: "lusna", "writer ending");
    };

    let reader = async move {
        let input = &mut [0u8; 4096];
        loop {
            let len = stream.read(input).await.unwrap().unwrap();
            if let Ok(string) = String::from_utf8(Vec::from(&input[..len])) {
                log::trace!(target: "lusna", "[Message]: {}", string);
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
            log::trace!(target: "lusna", "About to send (bind:{:?}->{:?}): {}", hole_punched_socket.socket.local_addr().unwrap(), hole_punched_socket.addr.natted, &input);
            hole_punched_socket.socket.send_to(input.as_bytes(), hole_punched_socket.addr.natted).await.unwrap();
        }

        log::trace!(target: "lusna", "writer ending");
    };

    let reader = async move {
        let input = &mut [0u8; 4096];
        loop {
            let len = hole_punched_socket.socket.recv(input).await.unwrap();
            if let Ok(string) = String::from_utf8(Vec::from(&input[..len])) {
                log::trace!(target: "lusna", "[Message]: {}", string);
            }
        }
    };

    tokio::select! {
            res0 = writer => res0,
            res1 = reader => res1
        }*/

    log::trace!(target: "lusna", "Quitting program serverside");
}