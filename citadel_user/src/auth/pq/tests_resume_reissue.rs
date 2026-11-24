//! A session that changes its own account's sign-in keeps its resume credential, re-bound; every
//! other credential issued before the change is refused.

use super::record::PqAuthRecord;
use super::server::{build_resume_challenge, reissue_grant, AccountAuth};
use super::tests::{register, CID};
use super::tests_resume::{issued, presented, resuming, HOUR_MS, HOUR_S, NOW};
use citadel_io::{tokio, ErrorCode};
use citadel_types::auth::SignInPolicy;
use std::time::Duration;

const DAY: Duration = Duration::from_secs(24 * HOUR_S);

fn changed(record: &PqAuthRecord) -> PqAuthRecord {
    let mut after = record.clone();
    after.policy = SignInPolicy::KeyOnly;
    after
}

/// Control: seal the re-issued body with `valid_until_utc` moved.
#[tokio::test]
async fn the_changing_sessions_credential_is_re_bound_and_expires_when_it_did() {
    let before = register("pw").await;
    let after = changed(&before);
    let credential = issued(&before, HOUR_S);
    let held = presented(&credential);
    let later = NOW + HOUR_MS / 2;
    let grant = reissue_grant(&resuming(DAY), CID, &before, &after, &held, later).unwrap();
    let kept = credential.reissued(grant).unwrap();
    assert_eq!(kept.valid_until_utc(), credential.valid_until_utc());
    assert_eq!(kept.issued_at_utc(), credential.issued_at_utc());

    let answer = |record: &PqAuthRecord, credential, now| {
        let (start, _) =
            super::client::ClientLogin::start_resume("alice", credential, NOW).unwrap();
        let account = AccountAuth::PostQuantum(record);
        build_resume_challenge(&resuming(DAY), CID, account, &start, now)
            .err()
            .map(|err| err.code)
    };
    assert_eq!(answer(&after, &kept, later), None);
    let revoked = Some(ErrorCode::ResumeCredentialRevoked);
    assert_eq!(answer(&after, &credential, later), revoked, "the old grant");
    let expired = Some(ErrorCode::ResumeCredentialExpired);
    assert_eq!(
        answer(&after, &kept, NOW + HOUR_MS),
        expired,
        "no longer than it was"
    );
}

/// Control: drop the `check` (or the binding comparison) in `reissue_grant`.
#[tokio::test]
async fn only_a_genuine_live_grant_of_the_account_as_it_stood_is_re_issued() {
    let before = register("pw").await;
    let after = changed(&before);
    let credential = issued(&before, HOUR_S);
    let held = presented(&credential);
    let reissue = |held, now| reissue_grant(&resuming(DAY), CID, &before, &after, held, now);
    assert!(reissue(&held, NOW + 1).is_some());
    assert!(reissue(&held, NOW + HOUR_MS).is_none(), "expired");

    let mut forged = held.clone();
    forged.grant.body.valid_until_utc += HOUR_MS;
    assert!(reissue(&forged, NOW + 1).is_none(), "altered");

    // A grant already revoked by an earlier change is not brought back by a later one.
    let stale = presented(&issued(&register("an older password").await, HOUR_S));
    assert!(reissue(&stale, NOW + 1).is_none(), "bound to another state");

    // What the client keeps is the same credential and nothing else.
    let mut moved = reissue(&held, NOW + 1).unwrap();
    moved.body.valid_until_utc += 1;
    assert!(credential.reissued(moved).is_err());
}
