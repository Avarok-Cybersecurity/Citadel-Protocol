use tokio::io::{BufReader, AsyncBufReadExt};
use hyxe_wire::udp_traversal::udp_hole_puncher::UdpHolePuncher;
use hyxe_wire::quic::QuicEndpointConnector;
use netbeam::sync::RelativeNodeType;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use std::sync::Arc;

fn setup_log() {
    let _ = env_logger::try_init();
    log::trace!(target: "lusna", "TRACE enabled");
    log::trace!(target: "lusna", "INFO enabled");
    log::warn!(target: "lusna", "WARN enabled");
    log::error!(target: "lusna", "ERROR enabled");
}

#[tokio::main]
async fn main() {
    setup_log();

    let server_stream = tokio::net::TcpStream::connect("51.81.86.78:25025").await.unwrap();

    log::trace!(target: "lusna", "Established TCP server connection");

    let hole_punched_socket = UdpHolePuncher::new(&NetworkEndpoint::register(RelativeNodeType::Initiator, server_stream).await.unwrap(), Default::default()).await.unwrap();
    let client_config = Arc::new(hyxe_wire::quic::insecure::rustls_client_config());
    log::trace!(target: "lusna", "Successfully hole-punched socket to peer @ {:?}", hole_punched_socket.addr);
    let (_conn, mut sink, mut stream) = hyxe_wire::quic::QuicClient::new_with_config(hole_punched_socket.socket, client_config).unwrap().connect_biconn(hole_punched_socket.addr.receive_address, "mail.satorisocial.com").await.unwrap();
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

    log::trace!(target: "lusna", "Quitting program clientside");
}