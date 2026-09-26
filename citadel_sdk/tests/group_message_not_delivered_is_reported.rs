#![cfg(not(target_family = "wasm"))]
//! A group message that is not delivered is reported to its sender, not dropped in silence.
//!
//! After a server restart the application still holds the group channel of the session that
//! ended. A message sent on it used to be dropped with a log line ("session is not connected")
//! while the send itself returned `Ok`, so the agent answered `GroupMessageSuccess` and nobody,
//! sender or member, ever learned the message went nowhere. The sender now receives
//! `MessageResponse { success: false }` on that channel, which the agent already turns into
//! `GroupMessageResponse { success: false }`.
//!
//! ```text
//! A: register → connect → create a group → disconnect
//! A: send on the group channel of the ended session
//! A must receive MessageResponse { success: false } for that group on the channel
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_send_on_an_ended_sessions_group_channel_is_reported_as_not_delivered() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(1);

        let (server, server_addr) = server_info::<StackedRatchet>();
        let name = format!("gnd_{}", &Uuid::new_v4().to_string()[..8]);
        let reported = Arc::new(AtomicBool::new(false));

        let client = {
            let reported = reported.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let _ = remote
                        .register_with_defaults(server_addr, &name, &name, PASSWORD)
                        .await?;
                    let conn = connect(&remote, &name).await?;
                    let mut channel = conn.create_group(None).await?;
                    let key = channel.key();
                    conn.disconnect().await?;

                    channel
                        .send_message(SecBuffer::from(b"into the void".to_vec()))
                        .await?;
                    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
                        loop {
                            match channel.recv().await {
                                Some(GroupBroadcastPayload::Event {
                                    payload: GroupBroadcast::MessageResponse { key: k, success },
                                }) if k == key => return Some(success),
                                Some(other) => {
                                    log::info!(target: "citadel", "while waiting for the refusal: {other:?}")
                                }
                                None => return None,
                            }
                        }
                    })
                    .await;
                    assert_eq!(
                        outcome,
                        Ok(Some(false)),
                        "the sender must be told the message was not delivered"
                    );
                    reported.store(true, Ordering::SeqCst);
                    drop(channel);
                    remote.shutdown().await
                },
            )
        };

        let client = DefaultNodeBuilder::default().build(client).unwrap();
        let task = async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = client => res.map(|_| ()),
            }
        };
        let result = tokio::time::timeout(Duration::from_secs(60), task)
            .await
            .expect("test timed out");
        assert!(result.is_ok(), "test failed: {result:?}");
        assert!(reported.load(Ordering::SeqCst));
    }
}
