//! A server holds every client to a bounded keep-alive timeout, and times out a session that
//! never sent a keep-alive. Timestamps are passed in: the check reads no clock of its own.

use super::super::test_support::state_container;
use super::*;
use citadel_io::tokio;

#[test]
fn a_client_cannot_switch_off_or_stretch_the_servers_keep_alive_check() {
    assert_eq!(
        server_keep_alive_timeout_ns(0),
        MIN_SERVER_KEEP_ALIVE_TIMEOUT_NS
    );
    assert_eq!(
        server_keep_alive_timeout_ns(-1),
        MIN_SERVER_KEEP_ALIVE_TIMEOUT_NS
    );
    assert_eq!(
        server_keep_alive_timeout_ns(i64::MAX),
        MAX_SERVER_KEEP_ALIVE_TIMEOUT_NS
    );
    let within = MIN_SERVER_KEEP_ALIVE_TIMEOUT_NS + 1;
    assert_eq!(server_keep_alive_timeout_ns(within), within);
}

#[test]
fn a_session_that_never_sent_a_keep_alive_times_out_from_its_start() {
    let timeout = MIN_SERVER_KEEP_ALIVE_TIMEOUT_NS;
    assert!(!keep_alive_timed_out(None, 1_000, 1_000 + timeout, timeout));
    assert!(keep_alive_timed_out(None, 1_000, 1_001 + timeout, timeout));
    // Once one has arrived, it is measured from the last.
    assert!(!keep_alive_timed_out(
        Some(5_000),
        1_000,
        1_001 + timeout,
        timeout
    ));
    assert!(keep_alive_timed_out(
        Some(5_000),
        1_000,
        5_001 + timeout,
        timeout
    ));
}

#[tokio::test]
async fn a_silent_session_times_out_though_it_never_sent_a_keep_alive() {
    let timeout = MIN_SERVER_KEEP_ALIVE_TIMEOUT_NS;
    let container = state_container(true, timeout).await;
    let inner = inner_state!(container);
    let since = inner.network_stats.measured_since_ns;
    assert!(!inner.keep_alive_subsystem_timed_out(since + timeout));
    assert!(inner.keep_alive_subsystem_timed_out(since + timeout + 1));
}
