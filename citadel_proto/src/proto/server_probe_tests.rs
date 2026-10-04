use super::*;
use citadel_io::tokio;
use embedded_semver::Semver;

fn version(major: usize, minor: usize, patch: usize) -> Option<u32> {
    Some(Semver::new(major, minor, patch).to_u32().unwrap())
}

#[test]
fn only_a_server_at_or_above_the_gate_is_probed() {
    let (major, minor, patch) = SERVER_PROBE_SINCE;
    assert!(server_answers_probes(Some(
        *crate::constants::PROTOCOL_VERSION
    )));
    assert!(server_answers_probes(version(
        major.into(),
        minor.into(),
        patch.into()
    )));
    assert!(
        !server_answers_probes(version(0, 12, 0)),
        "0.12.0 reads a probe as a keep-alive"
    );
    assert!(!server_answers_probes(None), "an unknown version is not");
    assert!(!server_answers_probes(Some(u32::MAX)));
}

#[tokio::test]
async fn an_answered_probe_reports_its_round_trip() {
    let probes = ServerProbes::default();
    let probe = probes.begin();
    assert!(probes.answer(probe.nonce()));
    match probe.outcome(Duration::from_secs(5)).await {
        ServerProbeOutcome::Ok(rtt) => assert!(rtt < Duration::from_secs(5)),
        other => panic!("expected Ok, got {other:?}"),
    }
    assert_eq!(probes.in_flight(), 0);
}

#[tokio::test]
async fn an_unanswered_probe_times_out_and_is_forgotten() {
    let probes = ServerProbes::default();
    let probe = probes.begin();
    let nonce = probe.nonce();
    let outcome = probe.outcome(Duration::from_millis(50)).await;
    assert!(
        matches!(outcome, ServerProbeOutcome::Timeout),
        "{outcome:?}"
    );
    assert_eq!(probes.in_flight(), 0);
    assert!(!probes.answer(nonce), "a late reply finds no probe");
}

#[test]
fn a_reply_answers_only_its_own_probe() {
    let probes = ServerProbes::default();
    let first = probes.begin();
    let second = probes.begin();
    assert_ne!(first.nonce(), second.nonce());
    assert!(!probes.answer(first.nonce() ^ second.nonce() ^ 1));
    assert!(probes.answer(second.nonce()));
    assert_eq!(probes.in_flight(), 1, "the first still waits");
    drop(first);
    assert_eq!(probes.in_flight(), 0, "dropping a probe forgets it");
}

#[tokio::test]
async fn an_answer_read_after_the_budget_is_a_timeout() {
    let probes = ServerProbes::default();
    let probe = probes.begin();
    assert!(probes.answer(probe.nonce()));
    let outcome = probe.outcome(Duration::ZERO).await;
    assert!(
        matches!(outcome, ServerProbeOutcome::Timeout),
        "{outcome:?}"
    );
}
