//! A connect whose caller stopped waiting is aborted, at whatever stage it reached (§9.1, S-C1).
//!
//! The caller of a connect that timed out or was signed out used to drop its future and leave
//! the node still connecting: the account's next login was refused ("Localhost is already trying
//! to connect", or "already in the process of connecting") until a reaper ran, 8 to 20 seconds
//! later. On a managed node the dropped connect's guard aborts it by its own ticket, and the next
//! connect is admitted at once. A proxy holds the first connect at the stage each test names.
#![cfg(not(target_family = "wasm"))]

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::link::{managed, proxy, saw, ManualClock, Plan, Seen};
    use crate::common::{NodeState, ReconnectionTestKernel};
    use citadel_io::tokio;
    use citadel_io::tokio::sync::oneshot;
    use citadel_proto::constants::TCP_CONN_TIMEOUT;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, LOCALHOST_STUN_SERVERS};
    use futures::StreamExt;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    /// Runs `handler` on a client node of `mode` beside a test server; a hang guard, not a
    /// latency assertion.
    async fn with_client<F, Fut>(mode: LinkManagerMode, plans: Vec<Plan>, handler: F)
    where
        F: FnOnce(
                NodeRemote<StackedRatchet>,
                SocketAddr,
                tokio::sync::mpsc::UnboundedReceiver<Seen>,
            ) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: Future<Output = Result<(), NetworkError>> + Send + 'static,
    {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();
        let (proxy_addr, seen) = proxy(server_addr, plans).await;
        let kernel = ReconnectionTestKernel::new(
            Arc::new(NodeState::default()),
            move |remote: NodeRemote<StackedRatchet>, _| handler(remote, proxy_addr, seen),
        );
        let mut builder = DefaultNodeBuilder::default();
        let client = builder
            .with_link_manager(mode)
            .with_stun_servers(LOCALHOST_STUN_SERVERS)
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
    }

    fn connect(user: Uuid, addr: SocketAddr) -> NodeRequest {
        NodeRequest::ConnectToHypernode(ConnectToHypernode {
            auth_request: AuthenticationRequest::transient(user, addr),
            connect_mode: ConnectMode::Standard { force_login: false },
            udp_mode: UdpMode::default(),
            keep_alive_timeout: None,
            session_password: Default::default(),
            session_security_settings: Default::default(),
        })
    }

    /// Starts a connect for `user` and drops it once the proxy has seen `stage`; then connects
    /// `user` again at once and returns that second connect's outcome.
    async fn drop_then_reconnect(
        remote: NodeRemote<StackedRatchet>,
        addr: SocketAddr,
        seen: &mut tokio::sync::mpsc::UnboundedReceiver<Seen>,
        stage: Seen,
    ) -> Result<(), NetworkError> {
        let user = Uuid::new_v4();
        let first = {
            let remote = remote.clone();
            tokio::spawn(async move {
                remote
                    .connect_with_defaults(AuthenticationRequest::transient(user, addr))
                    .await
                    .map(|_| ())
            })
        };
        saw(seen, stage).await;
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        remote
            .connect_with_defaults(AuthenticationRequest::transient(user, addr))
            .await
            .map(|_| ())
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_connect_dropped_mid_handshake_leaves_nothing_provisional() {
        let plans = vec![Plan::Hold { release: None }, Plan::Forward];
        with_client(
            managed(ManualClock::new()),
            plans,
            |remote, addr, mut seen| async move {
                let second =
                    drop_then_reconnect(remote.clone(), addr, &mut seen, Seen::ClientSpoke(0))
                        .await;
                assert!(second.is_ok(), "the next connect was refused: {second:?}");
                // The aborted connect's own transport was closed, not left to its login deadline.
                saw(&mut seen, Seen::ClientClosed(0)).await;
                remote.shutdown().await
            },
        )
        .await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_connect_dropped_while_dialling_leaves_nothing_provisional() {
        let plans = vec![Plan::Silent, Plan::Forward];
        with_client(
            managed(ManualClock::new()),
            plans,
            |remote, addr, mut seen| async move {
                let second =
                    drop_then_reconnect(remote.clone(), addr, &mut seen, Seen::Accepted(0)).await;
                assert!(second.is_ok(), "the next connect was refused: {second:?}");
                // The dial itself was stopped: left to run, it holds its socket until its own
                // deadline (TCP_CONN_TIMEOUT) and only then closes.
                tokio::time::timeout(TCP_CONN_TIMEOUT / 2, saw(&mut seen, Seen::ClientClosed(0)))
                    .await
                    .expect("the aborted dial ran on to its own deadline");
                remote.shutdown().await
            },
        )
        .await;
    }

    /// `Legacy` keeps today's behaviour, refusal included: what the managed tests above prove
    /// gone is still there without the manager.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_legacy_node_still_refuses_the_next_connect() {
        let plans = vec![Plan::Hold { release: None }, Plan::Forward];
        with_client(
            LinkManagerMode::Legacy,
            plans,
            |remote, addr, mut seen| async move {
                let second =
                    drop_then_reconnect(remote.clone(), addr, &mut seen, Seen::ClientSpoke(0))
                        .await;
                let refusal = second
                    .expect_err("a legacy node let the next connect in")
                    .into_string();
                assert!(refusal.contains("already trying to connect"), "{refusal}");
                remote.shutdown().await
            },
        )
        .await;
    }

    /// Only the ticket that requested a connect aborts it (owner Q12): an abort naming no connect
    /// changes nothing, and an abort of one connect leaves another running to success.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_abort_ends_only_the_connect_its_ticket_names() {
        let (release_b, released_b) = oneshot::channel();
        let plans = vec![
            Plan::Hold { release: None },
            Plan::Hold {
                release: Some(released_b),
            },
        ];
        with_client(
            managed(ManualClock::new()),
            plans,
            |remote, addr, mut seen| async move {
                let (a, b) = (remote.get_next_ticket(), remote.get_next_ticket());
                let _held_a = remote
                    .send_callback_subscription_custom_ticket(connect(Uuid::new_v4(), addr), a)
                    .await?;
                assert_eq!(seen.recv().await, Some(Seen::Accepted(0)));
                assert_eq!(seen.recv().await, Some(Seen::ClientSpoke(0)));
                let mut b_answers = remote
                    .send_callback_subscription_custom_ticket(connect(Uuid::new_v4(), addr), b)
                    .await?;
                assert_eq!(seen.recv().await, Some(Seen::Accepted(1)));
                assert_eq!(seen.recv().await, Some(Seen::ClientSpoke(1)));

                let nobody = remote.get_next_ticket();
                let _ = remote
                    .send(NodeRequest::AbortLink(AbortLink { ticket: nobody }))
                    .await?;
                let _ = remote
                    .send(NodeRequest::AbortLink(AbortLink { ticket: a }))
                    .await?;
                // The first thing the proxy sees after the aborts is A's transport closing.
                assert_eq!(seen.recv().await, Some(Seen::ClientClosed(0)));

                release_b.send(()).unwrap();
                let answer = b_answers.next().await.expect("B was never answered");
                assert!(
                    matches!(answer, NodeResult::ConnectSuccess(_)),
                    "B did not connect: {answer:?}"
                );
                remote.shutdown().await
            },
        )
        .await;
    }
}
