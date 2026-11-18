//! Identification models the NAT from the first three STUN answers. With four servers of which
//! three answer at once and one never does, it succeeds from the three, well inside its deadline.
#![cfg(not(target_family = "wasm"))]

use citadel_io::tokio;
use citadel_wire::nat_identification::{NatType, IDENTIFY_TIMEOUT};
use citadel_wire::stun_servers::StunServers;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use stun::message::{Message, BINDING_SUCCESS};
use stun::xoraddr::XorMappedAddress;

/// Answers every BINDING request immediately with `203.0.113.9:<source port>`.
fn spawn_answering_responder() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let mapped_ip = IpAddr::from_str("203.0.113.9").unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((len, from)) = socket.recv_from(&mut buf) {
            let mut request = Message::new();
            request.raw = buf[..len].to_vec();
            if request.decode().is_err() {
                continue;
            }
            let mut response = Message::new();
            response.transaction_id = request.transaction_id;
            response
                .build(&[
                    Box::new(BINDING_SUCCESS),
                    Box::new(XorMappedAddress {
                        ip: mapped_ip,
                        port: from.port(),
                    }),
                ])
                .unwrap();
            let _ = socket.send_to(&response.raw, from);
        }
    });
    addr
}

#[tokio::test]
async fn three_answers_out_of_four_servers_identify_the_nat() {
    // Bound and silent for the whole test: no ICMP, just no answer.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut servers: Vec<String> = (0..3)
        .map(|_| spawn_answering_responder().to_string())
        .collect();
    servers.push(silent.local_addr().unwrap().to_string());
    let servers = StunServers::new(servers).unwrap();

    let started = Instant::now();
    let result = tokio::time::timeout(
        IDENTIFY_TIMEOUT + Duration::from_secs(2),
        NatType::identify_timeout(IDENTIFY_TIMEOUT, &servers),
    )
    .await
    .expect("identify_timeout overran its own deadline");
    println!("identify took {:?}: {result:?}", started.elapsed());
    assert!(
        result.is_ok(),
        "three of four STUN servers answered, yet identification failed: {result:?}"
    );
    drop(silent);
}
