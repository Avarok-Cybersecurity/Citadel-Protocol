//! Every background P2P upgrade attempt reports its outcome — the path it attached, and a typed
//! reason for each stage that did not connect — on the channel (`PeerChannel::path_outcomes`)
//! and to the kernel (`NodeResult::PeerPathOutcome`), and both carry the same outcome.
//!
//! No assertion here is a latency: each is a path, a reason, or an equality.
#![cfg(not(target_family = "wasm"))]

mod relay_pair;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::relay_pair::pair::*;
    use citadel_io::tokio;
    use citadel_sdk::prelude::*;
    use citadel_sdk::remote_ext::results::PeerConnectSuccess;
    use citadel_sdk::test_common::{server_info, wait_for_peers};
    use std::sync::{Arc, Mutex};

    /// A TURN relay that refuses at once (a TCP port nothing listens on).
    fn refusing_relay() -> TurnRelayConfig {
        TurnRelayConfig::new(
            vec![
                TurnServerCredential::new("turn:127.0.0.1:1?transport=tcp", "user", "pass", None)
                    .unwrap(),
            ],
            TurnPolicy::RelayOnly,
        )
    }

    type Seen = Arc<Mutex<Vec<(usize, PeerPathOutcome)>>>;

    fn recorder() -> (Seen, PathObserver) {
        let seen: Seen = Default::default();
        let sink = seen.clone();
        (
            seen,
            Arc::new(move |me, o| sink.lock().unwrap().push((me, o))),
        )
    }

    /// The first attempt's outcome, as the channel publishes it.
    async fn first_outcome(conn: &PeerConnectSuccess<StackedRatchet>) -> PathAttemptOutcome {
        let mut outcomes = conn.channel.path_outcomes();
        let outcome = outcomes.wait_for(|o| o.is_some()).await.expect("cell gone");
        outcome.clone().unwrap()
    }

    /// The kernel was sent the same outcome the channel published, for the same connection. The
    /// kernel handles its events on its own task, so this waits for it (bounded: a hang guard).
    async fn kernel_saw(seen: &Seen, me: usize, conn: &PeerConnectSuccess<StackedRatchet>) {
        let published = conn.channel.p2p_path_cell().last_outcome().unwrap();
        let event = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let found = seen
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(who, _)| *who == me)
                    .cloned();
                if let Some((_, event)) = found {
                    return event;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("peer {me}: the kernel was sent no path outcome"));
        assert_eq!(event.outcome, published, "peer {me}");
        assert_eq!(event.session_cid, conn.channel.get_session_cid());
        assert_eq!(event.connection_id, conn.channel.connection_id());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_direct_win_reports_its_path_stages_and_time_to_connect() {
        let (seen, observe) = recorder();
        let checked = seen.clone();
        run_pair_on(
            server_info::<StackedRatchet>(),
            None,
            UdpMode::Disabled,
            Arc::new(move |me, conn: PeerConnectSuccess<StackedRatchet>| {
                let seen = checked.clone();
                Box::pin(async move {
                    assert_eq!(conn.channel.ensure_direct().await.unwrap(), P2pPath::Direct);
                    let outcome = first_outcome(&conn).await;
                    assert_eq!(outcome.peer_cid, conn.channel.get_peer_cid());
                    assert_eq!(outcome.attempt, 1);
                    assert_eq!(outcome.plan, PathPlanKind::DirectOnly);
                    assert_eq!(outcome.path, P2pPath::Direct, "peer {me}");
                    assert!(!outcome.relayed_both);
                    let stages: Vec<_> =
                        outcome.stages.iter().map(|s| (s.stage, s.result)).collect();
                    assert_eq!(
                        stages,
                        vec![
                            (PathStage::Coordination, Ok(())),
                            (PathStage::Direct, Ok(())),
                            (PathStage::Turn, Err(StageFailure::NotConfigured)),
                        ],
                        "peer {me}"
                    );
                    assert!(outcome.time_to_connect().is_some());
                    kernel_saw(&seen, me, &conn).await;
                    wait_for_peers().await;
                })
            }),
            observe,
        )
        .await;
        assert_eq!(seen.lock().unwrap().len(), 2, "one outcome per peer");
    }

    /// A relay-only plan against a relay that refuses: the punch is reported as skipped by
    /// policy, and TURN as failed — the allocating peer (lower CID) could not allocate, and the
    /// dialing peer was told its peer had nothing to offer.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_relay_reports_why_each_stage_did_not_connect() {
        let (seen, observe) = recorder();
        let checked = seen.clone();
        run_pair_on(
            server_info::<StackedRatchet>(),
            Some(refusing_relay()),
            UdpMode::Disabled,
            Arc::new(move |me, conn: PeerConnectSuccess<StackedRatchet>| {
                let seen = checked.clone();
                Box::pin(async move {
                    assert!(conn.channel.ensure_direct().await.is_err());
                    let outcome = first_outcome(&conn).await;
                    assert_eq!(outcome.plan, PathPlanKind::TurnOnly);
                    assert_eq!(outcome.path, P2pPath::ServerRelay);
                    assert_eq!(outcome.time_to_connect(), None);
                    assert_eq!(
                        outcome.failure(PathStage::Direct),
                        Some(StageFailure::SkippedByPolicy)
                    );
                    let allocator = conn.channel.get_session_cid() < conn.channel.get_peer_cid();
                    let expected = if allocator {
                        StageFailure::AllocationFailed
                    } else {
                        StageFailure::PeerUnavailable
                    };
                    assert_eq!(
                        outcome.failure(PathStage::Turn),
                        Some(expected),
                        "peer {me} (allocator: {allocator})"
                    );
                    kernel_saw(&seen, me, &conn).await;
                    wait_for_peers().await;
                })
            }),
            observe,
        )
        .await;
    }
}
