use citadel_sdk::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::main]
async fn main() {
    citadel_logging::setup_log();
    let addr = get_env("CITADEL_SERVER_ADDR");
    let finished = &AtomicBool::new(false);
    let client = citadel_sdk::prefabs::client::single_connection
    ::SingleClientServerConnectionKernel::new_register_defaults("Dummy user", "dummyusername", "notsecurepassword", addr, |_connection, remote| async move {
        finished.store(true, Ordering::SeqCst);
        remote.shutdown_kernel().await?;
        Ok(())
    }).unwrap();

    let _ = NodeBuilder::default()
        .with_node_type(NodeType::Peer)
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