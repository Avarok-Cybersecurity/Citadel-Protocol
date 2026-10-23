//! Both peers execute the plan their server stamps into the key exchange: the server's path
//! policy decides which paths a pair tries, and how long each attempt may take.
//!
//! ```text
//! server policy: Direct disabled            → the pair never punches, though loopback would work
//! server policy: Direct disabled, Turn 3 s  → a silent TURN server times out at 3 s, not 30 s
//! ```
//! Controls: with the default test policy the same pair connects directly
//! (`turn_relay_p2p::without_a_turn_config_the_pair_connects_directly`), and a silent relay is
//! given the 30 s every plan used before policies.
#![cfg(not(target_family = "wasm"))]

mod relay_pair;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::relay_pair::pair::*;
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::remote_ext::results::PeerConnectSuccess;
    use citadel_sdk::test_common::{server_test_node, wait_for_peers};
    use futures::StreamExt;
    use std::sync::Arc;
    use std::time::Duration;

    /// Every path for every class, except that `disabled` may not be used, and Turn attempts
    /// last `turn_timeout`.
    fn policy(disabled: PathKind, turn_timeout: Duration) -> PathPolicy {
        let rules = PathKind::ALL
            .into_iter()
            .map(|kind| PathRule {
                kind,
                enabled: kind != disabled,
                attempt_timeout: if kind == PathKind::Turn {
                    turn_timeout
                } else {
                    Duration::from_secs(30)
                },
                cost_weight: 1,
                classes: PathClasses::ALL,
            })
            .collect();
        PathPolicy::new(rules, PathClasses::NONE).unwrap()
    }

    fn server(
        policy: PathPolicy,
    ) -> (
        NodeFuture<'static, EmptyKernel<StackedRatchet>>,
        std::net::SocketAddr,
    ) {
        server_test_node(EmptyKernel::<StackedRatchet>::default(), move |builder| {
            let _ = builder.with_path_policy(policy);
        })
    }

    async fn first_outcome(conn: &PeerConnectSuccess<StackedRatchet>) -> PathAttemptOutcome {
        let mut outcomes = conn.channel.path_outcomes();
        let outcome = outcomes.wait_for(|o| o.is_some()).await.expect("cell gone");
        outcome.clone().unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_server_that_disables_direct_keeps_the_pair_off_the_punch() {
        run_pair_on(
            server(policy(PathKind::Direct, Duration::from_secs(30))),
            None,
            UdpMode::Disabled,
            Arc::new(move |me, conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    assert!(conn.channel.ensure_direct().await.is_err(), "peer {me}");
                    let outcome = first_outcome(&conn).await;
                    assert_eq!(outcome.plan, PathPlanKind::ServerOnly, "peer {me}");
                    assert_eq!(outcome.path, P2pPath::ServerRelay);
                    assert_eq!(
                        outcome.failure(PathStage::Direct),
                        Some(StageFailure::SkippedByPolicy),
                        "peer {me}: loopback NATs allow a punch; only the policy forbids it"
                    );
                    assert_eq!(
                        outcome.failure(PathStage::Turn),
                        Some(StageFailure::NotConfigured)
                    );
                    // The pair still talks, over the server relay.
                    let (mut tx, mut rx) = conn.channel.split();
                    tx.send(format!("hello from {me}").into_bytes())
                        .await
                        .unwrap();
                    let heard = rx.next().await.expect("the relay carries messages");
                    assert_eq!(heard.as_ref(), format!("hello from {}", 1 - me).as_bytes());
                    wait_for_peers().await;
                })
            }),
            Arc::new(|_, _| {}),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn each_path_is_attempted_for_its_rules_timeout() {
        // A TURN server that never answers: a bound socket nobody reads, so no ICMP refusal
        // ends the attempt early. Only the attempt timeout can.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let url = format!("turn:{}?transport=udp", silent.local_addr().unwrap());
        let relay = TurnRelayConfig::new(
            vec![TurnServerCredential::new(&url, "user", "pass", None).unwrap()],
            TurnPolicy::Fallback,
        );
        let timeout = Duration::from_secs(3);
        run_pair_on(
            server(policy(PathKind::Direct, timeout)),
            Some(relay),
            UdpMode::Disabled,
            Arc::new(move |me, conn: PeerConnectSuccess<StackedRatchet>| {
                Box::pin(async move {
                    assert!(conn.channel.ensure_direct().await.is_err(), "peer {me}");
                    let outcome = first_outcome(&conn).await;
                    assert_eq!(outcome.plan, PathPlanKind::TurnOnly, "peer {me}");
                    let turn = outcome
                        .stages
                        .iter()
                        .find(|s| s.stage == PathStage::Turn)
                        .expect("the Turn stage ran");
                    assert_eq!(turn.result, Err(StageFailure::Timeout), "peer {me}");
                    // Bounded by the rule's 3 s, far below the 30 s of a plan without policy.
                    assert!(
                        turn.elapsed >= timeout && turn.elapsed < Duration::from_secs(10),
                        "peer {me}: the Turn attempt ran {:?}",
                        turn.elapsed
                    );
                    wait_for_peers().await;
                })
            }),
            Arc::new(|_, _| {}),
        )
        .await;
        drop(silent);
    }
}
