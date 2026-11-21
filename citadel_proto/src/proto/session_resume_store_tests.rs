use super::StoredResume;
use citadel_io::time::{Duration, Instant};

const GRACE: Duration = Duration::from_secs(900);
const ENDED_MS: u64 = 1_760_000_000_000;

#[test]
fn records_decode_by_length() {
    assert_eq!(StoredResume::decode(&[]).unwrap(), StoredResume::LiveAtStop);
    let ended = StoredResume::decode(&ENDED_MS.to_be_bytes()).unwrap();
    assert_eq!(ended, StoredResume::EndedAtMs(ENDED_MS));
    assert!(StoredResume::decode(&[0u8; 7]).is_err());
}

#[test]
fn an_ended_record_counts_until_the_grace_after_its_end() {
    let started = Instant::now();
    let record = StoredResume::EndedAtMs(ENDED_MS);
    let grace_ms = GRACE.as_millis() as u64;
    assert!(record.within_grace(GRACE, ENDED_MS + grace_ms - 1, started, started));
    assert!(!record.within_grace(GRACE, ENDED_MS + grace_ms, started, started));
}

#[test]
fn a_record_live_at_the_stop_counts_only_within_the_grace_of_this_nodes_start() {
    let started = Instant::now();
    let record = StoredResume::LiveAtStop;
    assert!(record.within_grace(GRACE, 0, started, started));
    assert!(record.within_grace(
        GRACE,
        0,
        started,
        started + GRACE - Duration::from_millis(1)
    ));
    assert!(!record.within_grace(GRACE, 0, started, started + GRACE));
}

/// Control: drop the cap at the node's start and the late end exempts the login.
#[test]
fn an_end_written_after_this_node_started_counts_from_the_start() {
    let started = Instant::now();
    let now = started + Duration::from_secs(3);
    let now_ms = ENDED_MS + 3_000;
    // The stopped node's teardown wrote its end 2.5 s after this node started, within a second of now.
    let late = StoredResume::EndedAtMs(ENDED_MS + 2_500);
    let grace = Duration::from_secs(1);
    assert!(!late.within_grace(grace, now_ms, started, now));
    let early = StoredResume::EndedAtMs(ENDED_MS - 500);
    assert!(!early.within_grace(grace, now_ms, started, now));
    assert!(early.within_grace(
        grace,
        ENDED_MS + 400,
        started,
        started + Duration::from_millis(400)
    ));
}

#[test]
fn zero_grace_exempts_nothing() {
    let started = Instant::now();
    assert!(!StoredResume::LiveAtStop.within_grace(Duration::ZERO, 0, started, started));
    let ended = StoredResume::EndedAtMs(ENDED_MS);
    assert!(!ended.within_grace(Duration::ZERO, ENDED_MS, started, started));
}
