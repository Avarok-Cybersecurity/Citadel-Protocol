//! A C2S `Disconnect` says why the link closed when this node closed it on purpose.
//!
//! `Disconnect` carried a free-text message only, so an application could not tell its own
//! disconnect from a link that was lost. It now carries `reason` (`citadel_link::CloseReason`):
//! this node's disconnect is `Local(Shutdown)`, an abandon is `Local(Abandon)`, and a link that
//! was lost is `None`, never a deliberate reason.
#![cfg(not(target_family = "wasm"))]

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{managed, server_on, ManualClock, LOCALHOST_STUN_SERVERS};
    use futures::StreamExt;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    /// Connects, ends the session with `end(cid)`, and returns the `Disconnect` that answered.
    async fn reason_after(end: fn(u64) -> NodeRequest) -> Option<CloseReason> {
        citadel_logging::setup_log();
        // Both ends on clocks nobody moves: the login this test needs first cannot be ended by a
        // deadline, however slow the host (#391).
        let (server, server_addr) = server_on::<StackedRatchet>(ManualClock::new());
        let (reason_tx, reason_rx) = tokio::sync::oneshot::channel();
        let kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _| async move {
                let link = remote
                    .connect_with_defaults(
                        AuthenticationRequest::transient(Uuid::new_v4(), server_addr),
                        CertVerification::SelfSignedAccepted,
                    )
                    .await?;
                let mut answers = remote.send_callback_subscription(end(link.cid)).await?;
                while let Some(answer) = answers.next().await {
                    if let NodeResult::Disconnect(Disconnect { reason, .. }) = answer {
                        reason_tx.send(reason).unwrap();
                        break;
                    }
                }
                remote.shutdown().await
            },
        );
        let client = DefaultNodeBuilder::default()
            .with_link_manager(managed(ManualClock::new()))
            .with_stun_servers(LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .build(kernel)
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(120), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.map(|_| ())))),
                res = client => res.map(|_| ()),
            }
        })
        .await
        .expect("the test timed out");
        assert!(result.is_ok(), "{result:?}");
        reason_rx.await.expect("no Disconnect answered the request")
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_disconnect_this_node_asked_for_is_a_local_shutdown() {
        let reason = reason_after(|session_cid| {
            NodeRequest::DisconnectFromHypernode(DisconnectFromHypernode { session_cid })
        })
        .await;
        assert_eq!(reason, Some(CloseReason::Local(ShutdownReason::Shutdown)));
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_abandoned_session_is_a_local_abandon() {
        let reason =
            reason_after(|session_cid| NodeRequest::AbandonSession(AbandonSession { session_cid }))
                .await;
        assert_eq!(reason, Some(CloseReason::Local(ShutdownReason::Abandon)));
    }
}
