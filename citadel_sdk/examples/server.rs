use citadel_sdk::prefabs::server::empty::EmptyKernel;
use citadel_sdk::prelude::*;
use std::net::SocketAddr;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    citadel_logging::setup_log();
    let addr = get_env("CITADEL_SERVER_ADDR");
    let stun0 = get_env("STUN_0_ADDR");
    let stun1 = get_env("STUN_1_ADDR");
    let stun2 = get_env("STUN_2_ADDR");
    let server = EmptyKernel::default();
    let _ = NodeBuilder::default()
        .with_node_type(NodeType::Server(
            SocketAddr::from_str(addr.as_str()).unwrap(),
        ))
        .with_stun_servers([stun0, stun1, stun2])
        .build(server)
        .unwrap()
        .await
        .unwrap();
}

fn get_env(key: &'static str) -> String {
    if let Ok(env) = std::env::var(key) {
        env
    } else {
        panic!("Expected the env_var {key} set")
    }
}
