//! A hole punch whose attempt timer fires between the winner's `Winner` and the loser's
//! `WinnerCanEnd`.
//!
//! The winner announces the pair, the loser takes it and returns, and the release travels
//! back over a slow coordination path. A winner whose timer fired in that gap used to abandon
//! the attempt and retry against a peer that had already returned, so one side held a punched
//! socket and the other spent the rest of its budget and failed
//! (`test_dual_hole_puncher_high_lag_consensus`, macOS CI).
//!
//! The gap is about one round trip wide, so a sweep of attempt lengths across the time an
//! attempt takes to commit lands some of them inside it, whatever the host's speed. Every
//! punch must end the same way on both sides.
//!
//! Run: `cargo nextest run -p citadel_wire --release --test hole_punch_commit_at_the_timer`
#![cfg(not(feature = "localhost-testing"))]

use citadel_io::tokio;
use citadel_wire::stun_servers::StunServers;
use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use citadel_wire::udp_traversal::udp_hole_puncher::{EndpointHolePunchExt, PunchBudget};
use netbeam::sync::test_utils::create_streams_with_addrs_and_lag;
use std::time::Duration;

/// 150..300 ms a message: a third of `test_dual_hole_puncher_high_lag_consensus`, so an
/// attempt commits in seconds rather than the 15 s it takes there.
const LAG_MS: usize = 150;
/// The coarse sweep, from shorter than any attempt can commit to longer than any takes.
const COARSE_FROM: Duration = Duration::from_millis(2000);
const COARSE_STEP: Duration = Duration::from_millis(500);
const COARSE_TRIALS: u32 = 37;
/// The fine sweep, across the coarse step where punches start to succeed. The gap is a
/// one-way trip wide (150..300 ms here), so a step this fine puts several timers inside it.
const FINE_MARGIN: Duration = Duration::from_millis(500);
const FINE_TRIALS: u32 = 60;

fn silent_stun_servers() -> (Vec<std::net::UdpSocket>, StunServers) {
    let sockets = (0..3)
        .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let addrs = sockets
        .iter()
        .map(|s| s.local_addr().unwrap().to_string())
        .collect::<Vec<_>>();
    (
        sockets,
        StunServers::new(addrs).expect("three distinct local sockets"),
    )
}

fn container() -> HolePunchConfigContainer {
    HolePunchConfigContainer::new(
        |plaintext| plaintext.into(),
        |ciphertext| Some(ciphertext.into()),
    )
}

/// `(server punched, client punched)` for one punch with `attempt` per attempt on both sides.
async fn punch(servers: StunServers, attempt: Duration) -> (bool, bool) {
    let budget = PunchBudget::per_attempt(attempt);
    let (server_stream, client_stream) = create_streams_with_addrs_and_lag(LAG_MS).await;
    let server_servers = servers.clone();
    let server = tokio::task::spawn(async move {
        server_stream
            .begin_udp_hole_punch(container(), server_servers, budget)
            .await
            .is_ok()
    });
    let client = tokio::task::spawn(async move {
        client_stream
            .begin_udp_hole_punch(container(), servers, budget)
            .await
            .is_ok()
    });
    let (server, client) = tokio::join!(server, client);
    (server.unwrap(), client.unwrap())
}

/// Punches once per attempt length in `attempts`, all at once.
async fn sweep(servers: &StunServers, attempts: &[Duration]) -> Vec<(Duration, (bool, bool))> {
    let outcomes = futures::future::join_all(
        attempts
            .iter()
            .map(|attempt| punch(servers.clone(), *attempt)),
    )
    .await;
    let outcomes = attempts.iter().copied().zip(outcomes).collect::<Vec<_>>();
    println!("(attempt, (server punched, client punched)): {outcomes:?}");
    outcomes
}

fn assert_agreed(outcomes: &[(Duration, (bool, bool))]) {
    let one_sided = outcomes
        .iter()
        .filter(|(_, (server, client))| server != client)
        .collect::<Vec<_>>();
    assert!(
        one_sided.is_empty(),
        "one side punched and the other did not: {one_sided:?}"
    );
}

#[tokio::test]
async fn both_sides_end_an_attempt_the_same_way_wherever_its_timer_fires() {
    citadel_logging::setup_log();
    let (_silent, servers) = silent_stun_servers();

    let coarse = (0..COARSE_TRIALS)
        .map(|i| COARSE_FROM + COARSE_STEP * i)
        .collect::<Vec<_>>();
    let coarse = sweep(&servers, &coarse).await;
    assert_agreed(&coarse);
    // The sweep must straddle the commit: one where every punch failed, or every one
    // succeeded, never put a timer inside the gap and proves nothing.
    let first_punched = coarse
        .iter()
        .find(|(_, (server, client))| *server && *client)
        .map(|(attempt, _)| *attempt)
        .expect("no attempt length was long enough to punch");
    assert!(
        first_punched > COARSE_FROM,
        "every attempt length punched, so none fired before the commit"
    );

    let from = first_punched.saturating_sub(COARSE_STEP + FINE_MARGIN);
    let step = (COARSE_STEP + FINE_MARGIN * 2) / FINE_TRIALS;
    let fine = (0..FINE_TRIALS)
        .map(|i| from + step * i)
        .collect::<Vec<_>>();
    assert_agreed(&sweep(&servers, &fine).await);
}
