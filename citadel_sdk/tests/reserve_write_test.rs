#![cfg(not(target_family = "wasm"))]
//! End-to-end test for the fill-in-place send API (`PeerChannelSendHalf::reserve_write`).
//!
//! The client serializes each message directly into the reserved payload buffer (no
//! caller-side staging allocation); the server echoes it back and the client verifies the
//! bytes are byte-identical — proving the fill reaches the wire and round-trips intact.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info_reactive;
    use futures::StreamExt;
    use std::time::Duration;
    use uuid::Uuid;

    fn expected_message(i: usize) -> Vec<u8> {
        format!("reserve_write payload #{i} — fill in place").into_bytes()
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_reserve_write_round_trip() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        // Server: echo every received message back to the client.
        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            move |mut connection| async move {
                citadel_sdk::test_common::wait_for_peers().await;
                let channel = connection.take_channel().unwrap();
                let (mut tx, mut rx) = channel.split();
                while let Some(msg) = rx.next().await {
                    tx.send(msg).await?;
                }
                Ok(())
            },
            |_| {},
        );

        let uuid = Uuid::new_v4();
        let username = format!("rsw_{}", &uuid.to_string()[..8]);
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
                citadel_sdk::test_common::wait_for_peers().await;
                let channel = conn.take_channel().unwrap();
                let (mut tx, mut rx) = channel.split();

                const COUNT: usize = 5;

                // Send each message by filling the reserved payload buffer directly.
                for i in 0..COUNT {
                    let payload = expected_message(i);
                    tx.reserve_write(payload.len(), |buf| {
                        buf.copy_from_slice(&payload);
                        Ok(())
                    })
                    .await?;
                }

                // Verify each echo is byte-identical to what we filled in place.
                for i in 0..COUNT {
                    let echoed = rx
                        .next()
                        .await
                        .unwrap_or_else(|| panic!("Expected echo message {i}"));
                    assert_eq!(
                        echoed.as_ref(),
                        expected_message(i).as_slice(),
                        "reserve_write payload {i} did not round-trip intact"
                    );
                }

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
            panic!("reserve_write test failed: {e:?}");
        }
    }
}
