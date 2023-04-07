use citadel_sdk::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use citadel_network::{NetworkManager, Endpoint, Message};

#[tokio::main]
async fn main() {
    citadel_logging::setup_log();
    let addr = get_env("CITADEL_SERVER_ADDR");
    let stun0 = get_env("STUN_0_ADDR");
    let stun1 = get_env("STUN_1_ADDR");
    let stun2 = get_env("STUN_2_ADDR");

    let finished = &AtomicBool::new(false);
    let client = citadel_sdk::prefabs::client::single_connection
    ::SingleClientServerConnectionKernel::new_register("Dummy user", "dummyusername", "notsecurepassword", addr, UdpMode::Enabled, Default::default(), |mut connection, remote| async move {
        let chan = connection.udp_channel_rx.take();
        tokio::task::spawn(citadel_sdk::test_common::udp_mode_assertions(UdpMode::Enabled, chan))
            .await.map_err(|err| NetworkError::Generic(err.to_string()))?;
        finished.store(true, Ordering::SeqCst);
        remote.shutdown_kernel().await?;
        Ok(())
    }).unwrap();

    let _ = NodeBuilder::default()
        .with_node_type(NodeType::Peer)
        .with_stun_servers([stun0, stun1, stun2])
        .build(client)
        .unwrap()
        .await
        .unwrap();

    assert!(finished.load(Ordering::SeqCst));
}

fn get_env(key: &'static str) -> String {
    if let Ok(env) = std::env::var(key) {
        env
    } else {
        panic!("Expected the env_var {key} set")
    }
}

use citadel_network::{NetworkManager, Endpoint, Message};

fn main() {
    let mut network_manager = NetworkManager::new().unwrap(); //netowrk manager use

    let endpoint = Endpoint::new("ping-pong-client").unwrap(); //set up an endpoint for message.
    network_manager.create_endpoint(&endpoint).unwrap();

    //set up data unwrapper
    endpoint.send_data(b"ping").unwrap(); 

    let mut incoming_messages = endpoint.incoming().unwrap();

    loop {
        let message = incoming_messages.next().unwrap(); //keep receiving messages until we get pong from server
        match message {
            Message::Data(data) => {
                if data == b"pong" {
                    break;
                }
            },
            _ => ()
        }
    }
}






