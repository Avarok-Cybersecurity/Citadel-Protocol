use citadel_io::tokio;
use citadel_sdk::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::main]
async fn main() {
    citadel_logging::setup_log();
    let addr = get_env("CITADEL_SERVER_ADDR");
    let my_peer_id = get_env("MY_PEER_ID");
    let do_exit = get_env("DO_EXIT") == "true";
    let other_peer_id = get_env("OTHER_PEER_ID");
    let stun0 = get_env("STUN_0_ADDR");
    let stun1 = get_env("STUN_1_ADDR");
    let stun2 = get_env("STUN_2_ADDR");

    let agg = PeerConnectionSetupAggregator::default()
        .with_peer_custom(other_peer_id)
        .with_udp_mode(UdpMode::Enabled)
        .ensure_registered()
        .add();

    let server_connection_settings =
        DefaultServerConnectionSettingsBuilder::credentialed_registration(
            addr,
            my_peer_id,
            "dunny name",
            "password",
        )
        .build()
        .unwrap();

    let finished = &AtomicBool::new(false);
    let peer = citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel::new(
        server_connection_settings,
        agg,
        |mut connection, remote| async move {
            let mut connection = connection.recv().await.unwrap()?;
            let chan = connection.udp_channel_rx.take();
            citadel_io::tokio::task::spawn(citadel_sdk::test_common::udp_mode_assertions(
                UdpMode::Enabled,
                chan,
            ))
            .await
            .map_err(|err| NetworkError::Generic(err.to_string()))?;
            finished.store(true, Ordering::SeqCst);
            if do_exit {
                remote.shutdown_kernel().await?;
            }
            Ok(())
        },
    );

    let _ = DefaultNodeBuilder::default()
        .with_node_type(NodeType::Peer)
        .with_stun_servers([stun0, stun1, stun2])
        .build(peer)
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
