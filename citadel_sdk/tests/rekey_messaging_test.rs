//! Minimal test: Rekey + Messaging (no reconnection)
//!
//! This isolates whether rekey + messaging works without disconnect/reconnect.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info_reactive;
    use futures::StreamExt;
    use std::time::Duration;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_rekey_then_messaging() {
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
        let username = format!("rkm_{}", &uuid.to_string()[..8]);
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

                log::info!("[Client] Starting rekey...");
                // Rekey to advance ratchet version
                let rekey_result = conn.rekey().await?;
                log::info!("[Client] Rekey result: {:?}", rekey_result);
                assert_eq!(rekey_result, Some(1), "First rekey should give version 1");

                log::info!("[Client] Taking channel...");
                // Take channel and send messages
                let channel = conn.take_channel().unwrap();
                let (mut tx, mut rx) = channel.split();

                // Send 5 messages
                for i in 0..5 {
                    let msg = format!("Message {}", i);
                    log::info!("[Client] Sending message {}", i);
                    tx.send(SecBuffer::from(msg.as_bytes())).await?;
                }
                log::info!("[Client] All messages sent");

                // Receive 5 echoed messages
                for i in 0..5 {
                    log::info!("[Client] Waiting for echo {}", i);
                    let msg = rx.next().await;
                    assert!(msg.is_some(), "Expected echo message {}", i);
                    log::info!("[Client] Received echo {}", i);
                }

                log::info!("[Client] Test complete - rekey + messaging works!");
                conn.shutdown_kernel().await
            },
        );

        let client = NodeBuilder::default().build(client_kernel).unwrap();

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
