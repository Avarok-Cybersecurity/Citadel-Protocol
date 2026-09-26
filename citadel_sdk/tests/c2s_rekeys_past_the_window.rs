#![cfg(not(target_family = "wasm"))]
//! C2S messaging across more rekeys than the toolset holds.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info_reactive;
    use futures::StreamExt;
    use std::time::Duration;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn c2s_messages_survive_rekeys_past_the_toolset_window() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        // Server setup - echo messages back (NO rekey on server side)
        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            move |mut connection| async move {
                log::info!("[Server] Connection received, waiting for peers");
                citadel_sdk::test_common::wait_for_peers().await;
                log::info!("[Server] Taking channel");
                let channel = connection.take_channel().unwrap();
                let (mut tx, mut rx) = channel.split();

                log::info!("[Server] Starting echo loop");
                // Echo messages back
                while let Some(msg) = rx.next().await {
                    log::info!("[Server] Received message, echoing back");
                    tx.send(msg).await?;
                }

                log::info!("[Server] Echo loop ended (client closed channel)");
                Ok(())
            },
            |_| {},
        );

        let uuid = Uuid::new_v4();
        let username = format!("rkw_{}", &uuid.to_string()[..8]);
        let password = "password123";

        let client_kernel = citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel::new(
            citadel_sdk::prefabs::client::ServerConnectionSettingsBuilder::<StackedRatchet, _>::credentialed_registration(
                server_addr,
                username.as_str(),
                username.as_str(),
                password,
            )
            .with_udp_mode(UdpMode::Disabled)
            .build()
            .unwrap(),
            move |mut conn| async move {
                log::info!("[Client] Connected, waiting for peers");
                citadel_sdk::test_common::wait_for_peers().await;

                // Live, every session died once its C2S ratchet had to truncate: latest_usable
                // stuck at 4 while the toolset held 5..=9. Past the window, then past it again.
                let channel = conn.take_channel().unwrap();
                let (mut tx, mut rx) = channel.split();
                // A rekey that meets one the messages triggered answers None (contention); what
                // must hold is that every message still gets through, round after round.
                for round in 1..=40u32 {
                    let _ = conn.rekey().await?;
                    let msg = format!("after rekey {round}");
                    tx.send(SecBuffer::from(msg.as_bytes())).await?;
                    let echo = citadel_io::tokio::time::timeout(Duration::from_secs(10), rx.next()).await;
                    assert!(matches!(echo, Ok(Some(_))), "no echo after rekey {round}");
                }
                log::info!("[Client] Test complete - rekey + messaging works!");
                conn.shutdown_kernel().await
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();

        let task = async move {
            citadel_io::tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = client => client_res
            }
        };

        let result = citadel_io::tokio::time::timeout(Duration::from_secs(60), task)
            .await
            .expect("Test timed out");

        if let Err(e) = result {
            panic!("Test failed: {:?}", e);
        }
        log::info!("Rekey + Messaging test PASSED");
    }
}
