//! A hole punch's retries must stay paired across a one-sided delay.
//!
//! Each side arms its own per-attempt timer and nothing on the wire says which
//! attempt a message belongs to, nor tells the peer that an attempt was
//! abandoned. So if B starts (or resumes) its punch `skew` after A, every one
//! of B's attempts runs `skew` behind A's: A's attempt n and B's attempt n
//! overlap for only `attempt - skew`, and the retry re-arms both timers with
//! the same offset. Once that overlap is shorter than one exchange, no retry
//! can ever succeed, however many remain, and a partial overlap can let one
//! side finish while the other times out.

use super::{UdpHolePuncher, MAX_RETRIES};
use citadel_io::tokio;
use netbeam::sync::test_utils::create_streams_with_addrs_and_lag;
use std::time::Duration;

/// Per-message coordination lag. At 50 ms one full exchange takes ~1.4 s here.
const LAG_MS: usize = 50;
/// Roughly three exchanges: a generous window, not a tight one.
const ATTEMPT: Duration = Duration::from_secs(4);
/// B is late by less than one attempt window; A's first attempt is still
/// running when B's begins.
const SKEW: Duration = Duration::from_millis(3400);

async fn punch(endpoint: &netbeam::sync::network_endpoint::NetworkEndpoint) -> Result<(), String> {
    UdpHolePuncher::new_timeout(endpoint, Default::default(), ATTEMPT)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn a_one_sided_delay_shorter_than_an_attempt_does_not_fail_the_punch() {
    citadel_logging::setup_log();
    let (a, b) = create_streams_with_addrs_and_lag(LAG_MS).await;

    let side_a = punch(&a);
    let side_b = async {
        tokio::time::sleep(SKEW).await;
        punch(&b).await
    };
    // Every attempt of both sides, plus the offset; beyond this a side hung.
    let envelope = ATTEMPT * (MAX_RETRIES as u32 + 1) + SKEW;
    let (res_a, res_b) = tokio::time::timeout(envelope, async { tokio::join!(side_a, side_b) })
        .await
        .expect("a side never resolved its hole punch");

    assert_eq!(
        res_a.is_ok(),
        res_b.is_ok(),
        "one-sided outcome: A={res_a:?} B={res_b:?}"
    );
    assert!(
        res_a.is_ok() && res_b.is_ok(),
        "both sides were healthy after a delay shorter than one attempt, with \
         {} retries left, yet the punch failed: A={res_a:?} B={res_b:?}",
        MAX_RETRIES - 1
    );
}
