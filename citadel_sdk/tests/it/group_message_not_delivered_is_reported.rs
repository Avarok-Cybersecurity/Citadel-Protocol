#![cfg(not(target_family = "wasm"))]
//! A group message that is not delivered is reported to its sender, not dropped in silence.
//!
//! After a server restart the application still holds the group channel of the session that
//! ended. A message sent on it used to be dropped with a log line ("session is not connected")
//! while the send itself returned `Ok`, so the agent answered `GroupMessageSuccess` and nobody,
//! sender or member, ever learned the message went nowhere. The sender now receives
//! `MessageResponse` on that channel saying the message was not relayed because its session
//! ended.
//!
//! ```text
//! A: register → connect → create a group → disconnect
//! A: send on the group channel of the ended session
//! A must receive MessageResponse { NotRelayed(SessionEnded) } for that group on the channel
//! ```
//!
//! A send that has its place in the session's queue as the session ends is reported too: the
//! session, draining its queue, waits for it to write rather than reading the queue empty.
//!
//! ```text
//! A: register → connect → create a group; a send takes its place and is held
//! A: disconnect; the session starts draining; the held send writes
//! A must receive MessageResponse { NotRelayed(SessionEnded) } for that group on the channel
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use citadel_io::tokio;
    use citadel_proto::test_hooks::{hold_group_send, observe_session_drains};
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_info;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_send_on_an_ended_sessions_group_channel_is_reported_as_not_delivered() {
        reported_after(false).await
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_send_writing_as_its_session_drains_is_reported_as_not_delivered() {
        reported_after(true).await
    }

    /// Disconnects, then sends; or, `while_draining`, sends with the write held until the
    /// session has started draining its queue. Either way the send must be reported.
    async fn reported_after(while_draining: bool) {
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
                        .register_with_defaults(
                            server_addr,
                            &name,
                            &name,
                            PASSWORD,
                            CertVerification::SelfSignedAccepted,
                        )
                        .await?;
                    let conn = connect(&remote, &name).await?;
                    let mut channel = conn.create_group(None).await?;
                    let key = channel.key();
                    let message = || SecBuffer::from(b"into the void".to_vec());
                    if while_draining {
                        let mut hold = hold_group_send(conn.cid);
                        let mut drains = observe_session_drains();
                        let (sent, disconnected) =
                            tokio::join!(channel.send_message(message()), async {
                                hold.reserved().await;
                                let disconnected = conn.disconnect().await;
                                while drains.recv().await.expect("drains are observed")
                                    != Some(conn.cid)
                                {}
                                hold.release();
                                disconnected
                            });
                        disconnected?;
                        sent?;
                    } else {
                        conn.disconnect().await?;
                        channel.send_message(message()).await?;
                    }
                    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
                        loop {
                            match channel.recv().await {
                                Some(GroupBroadcastPayload::Event {
                                    payload: GroupBroadcast::MessageResponse { key: k, delivery, .. },
                                }) if k == key => return Some(delivery),
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
                        Ok(Some(GroupDelivery::NotRelayed(NotRelayed::SessionEnded))),
                        "the sender must be told the message was not delivered"
                    );
                    reported.store(true, Ordering::SeqCst);
                    drop(channel);
                    remote.shutdown().await
                },
            )
        };

        let client = citadel_sdk::test_common::node_builder()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .build(client)
            .unwrap();
        let task = async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = client => res.map(|_| ()),
            }
        };
        let result = citadel_io::time::runnable_timeout(Duration::from_secs(60), task)
            .await
            .expect("test timed out");
        assert!(result.is_ok(), "test failed: {result:?}");
        assert!(reported.load(Ordering::SeqCst));
    }
}
