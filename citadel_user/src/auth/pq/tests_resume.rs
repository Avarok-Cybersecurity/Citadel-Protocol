//! Resume credentials through the client and server functions, with no transport in between. The
//! server functions are called directly, so nothing here depends on a client having checked
//! anything first.

use super::client::{ClientLogin, ClientProof};
use super::login_transcript;
use super::messages::{LoginProof, LoginStart};
use super::record::PqAuthRecord;
use super::resume::{DeviceKey, PresentedResume, ResumeCredential, ResumePolicy};
use super::server::{
    build_resume_challenge, grant_after, issue_grant, AccountAuth, PqAuthServerSettings,
    VerifiedLogin,
};
use super::tests::{begin, complete, register, sent, settings, CID};
use citadel_io::{tokio, ErrorCode, NetworkError};
use citadel_types::auth::{SessionScope, SignInPolicy};
use std::time::Duration;

pub(crate) const NOW: u64 = 1_700_000_000_000;
pub(crate) const HOUR_S: u64 = 3_600;
pub(crate) const HOUR_MS: u64 = HOUR_S * 1_000;
pub(crate) const DAY: Duration = Duration::from_secs(24 * HOUR_S);

pub(crate) fn resuming(max: Duration) -> PqAuthServerSettings {
    settings().with_resume(ResumePolicy::new(max).unwrap())
}

/// A credential issued at `NOW` for `lifetime_s` by a server whose maximum is a day.
pub(crate) fn issued(record: &PqAuthRecord, lifetime_s: u64) -> ResumeCredential {
    let device = DeviceKey::generate();
    let request = device.request(lifetime_s).unwrap();
    let grant = issue_grant(&resuming(DAY), CID, record, &request, NOW).unwrap();
    ResumeCredential::accept(grant, device, CID, &request).unwrap()
}

/// What `credential` presents, built without the client's own expiry check.
pub(crate) fn presented(credential: &ResumeCredential) -> PresentedResume {
    credential.present(credential.issued_at_utc()).unwrap().0
}

pub(crate) fn start_with(presented: PresentedResume) -> LoginStart {
    let (mut start, _) = ClientLogin::start("alice", None, None).unwrap();
    start.resume_credential = Some(presented);
    start
}

/// The server's answer to `presented` at `now`, on a server whose maximum is `max`.
pub(crate) fn refusal(
    max: Duration,
    record: &PqAuthRecord,
    presented: PresentedResume,
    now: u64,
) -> Option<ErrorCode> {
    let account = AccountAuth::PostQuantum(record);
    build_resume_challenge(&resuming(max), CID, account, &start_with(presented), now)
        .err()
        .map(|err| err.code)
}

/// A whole resume at `now`: the client's start, the server's challenge, the proof, the check.
pub(crate) async fn resume(
    record: &PqAuthRecord,
    credential: &ResumeCredential,
    now: u64,
) -> Result<VerifiedLogin, NetworkError> {
    let (start, client) = ClientLogin::start_resume("alice", credential, now)?;
    let account = AccountAuth::PostQuantum(record);
    let (challenge, expected) = build_resume_challenge(&resuming(DAY), CID, account, &start, now)?;
    let transcript = login_transcript(CID, &start, &sent(&challenge));
    let ClientProof::Factors {
        proof: LoginProof::Factors(finish),
        ..
    } = client.respond(&challenge, &transcript, None).await?
    else {
        panic!("not a factor proof");
    };
    expected.bind(transcript).verify(&finish)
}

#[tokio::test]
async fn a_credential_signs_in_with_no_factor_of_the_account() {
    let record = register("pw").await;
    let credential = issued(&record, HOUR_S);
    assert_eq!(credential.valid_until_utc(), NOW + HOUR_MS);
    let verified = resume(&record, &credential, NOW + HOUR_MS - 1)
        .await
        .unwrap();
    assert_eq!(verified.scope, SessionScope::Full);
    assert!(!verified.by_factors, "a resume earns no new credential");
    // Control: record the resume key as used, and the account's record refuses the sign-in.
    let mut stored = record.clone();
    stored.record_use(&verified.used, NOW).unwrap();
    assert_eq!(stored, record, "a resume marks no factor of the account");

    // Control: drop `by_factors` from `grant_after`, and a resume renews itself for ever.
    let device = DeviceKey::generate();
    let request = device.request(HOUR_S).unwrap();
    let after = |verified: &VerifiedLogin| {
        grant_after(&resuming(DAY), CID, &record, verified, &request, NOW).is_some()
    };
    assert!(!after(&verified), "a resume was given a new credential");
    let full = complete(begin(Some(&record), "alice", Some("pw"), None))
        .await
        .unwrap();
    assert!(after(&full));
    let recovery = VerifiedLogin {
        scope: SessionScope::Recovery,
        ..full
    };
    assert!(
        !after(&recovery),
        "a recovery session was given a credential"
    );
}

/// Control: drop the expiry comparison in `server::resume::check`.
#[tokio::test]
async fn the_server_refuses_an_expired_grant_by_name_whatever_the_client_checked() {
    let record = register("pw").await;
    let credential = issued(&record, HOUR_S);
    let at = |now| refusal(DAY, &record, presented(&credential), now);
    assert_eq!(at(NOW + HOUR_MS - 1), None);
    assert_eq!(at(NOW + HOUR_MS), Some(ErrorCode::ResumeCredentialExpired));
    assert_eq!(at(u64::MAX), Some(ErrorCode::ResumeCredentialExpired));
}

/// Control: drop the check in `ResumeCredential::present`.
#[tokio::test]
async fn the_client_does_not_send_an_expired_credential() {
    let record = register("pw").await;
    let credential = issued(&record, HOUR_S);
    assert!(!credential.expired_at(NOW + HOUR_MS - 1));
    assert!(credential.expired_at(NOW + HOUR_MS));
    let refused = ClientLogin::start_resume("alice", &credential, NOW + HOUR_MS);
    assert_eq!(
        refused.err().unwrap().code,
        ErrorCode::ResumeCredentialExpired
    );
}

/// Control: leave a field out of `PqAuthRecord::resume_binding`.
#[tokio::test]
async fn a_change_to_the_accounts_sign_in_revokes_every_grant_before_it() {
    let record = register("pw").await;
    let credential = issued(&record, HOUR_S);
    let other = register("another password").await;
    let key = other.factors()[0].ek.clone();
    let revoked = Some(ErrorCode::ResumeCredentialRevoked);
    let after = |change: &dyn Fn(&mut PqAuthRecord)| {
        let mut changed = record.clone();
        change(&mut changed);
        refusal(DAY, &changed, presented(&credential), NOW + 1)
    };

    let new_password = |r: &mut PqAuthRecord| r.set_password(key.clone(), r.salt_user, r.ksf, 9);
    assert_eq!(after(&new_password), revoked, "a new password");
    let new_salt = |r: &mut PqAuthRecord| r.salt_user[0] ^= 1;
    assert_eq!(after(&new_salt), revoked, "a new password salt");
    let new_policy = |r: &mut PqAuthRecord| r.policy = SignInPolicy::KeyOnly;
    assert_eq!(after(&new_policy), revoked, "a new policy");
    let new_phrase = |r: &mut PqAuthRecord| r.replace_recovery_phrase(key.clone(), 9);
    assert_eq!(after(&new_phrase), revoked, "a new factor");

    let renamed = |r: &mut PqAuthRecord| r.rename(1, "Renamed".into()).unwrap();
    assert_eq!(after(&renamed), None, "a label is not the sign-in");
    let used = |r: &mut PqAuthRecord| r.record_use(&[1], 9).unwrap();
    assert_eq!(after(&used), None, "nor is when a factor was last used");
}

/// Control: remove the `min` in `ResumePolicy::granted_ms`, then in `honoured_until`.
#[tokio::test]
async fn a_lifetime_is_never_longer_than_the_servers_maximum() {
    let record = register("pw").await;
    let week = issued(&record, 7 * 24 * HOUR_S);
    assert_eq!(
        week.valid_until_utc(),
        NOW + 24 * HOUR_MS,
        "clamped when issued"
    );
    let short = issued(&record, HOUR_S);
    assert_eq!(
        short.valid_until_utc(),
        NOW + HOUR_MS,
        "a shorter ask is kept"
    );

    // The maximum was lowered after the grant was issued: the grant is honoured no longer.
    let lowered = Duration::from_secs(HOUR_S / 2);
    let at = |now| refusal(lowered, &record, presented(&short), now);
    assert_eq!(at(NOW + HOUR_MS / 2 - 1), None);
    assert_eq!(
        at(NOW + HOUR_MS / 2),
        Some(ErrorCode::ResumeCredentialExpired)
    );

    let device = DeviceKey::generate();
    let none = device.request(0).unwrap();
    assert!(issue_grant(&resuming(DAY), CID, &record, &none, NOW).is_none());
    let asked = device.request(HOUR_S).unwrap();
    assert!(issue_grant(&settings(), CID, &record, &asked, NOW).is_none());
    assert!(ResumePolicy::new(Duration::from_millis(999)).is_err());
}

#[tokio::test]
async fn the_client_keeps_only_the_grant_it_asked_for() {
    let record = register("pw").await;
    let device = DeviceKey::generate();
    let request = device.request(HOUR_S).unwrap();
    let grant = issue_grant(&resuming(DAY), CID, &record, &request, NOW).unwrap();
    let accept = |grant, device: &DeviceKey, cid| {
        ResumeCredential::accept(grant, device.clone(), cid, &request).is_ok()
    };
    assert!(accept(grant, &device, CID));
    assert!(!accept(grant, &device, CID + 1), "another account's");
    assert!(!accept(grant, &DeviceKey::generate(), CID), "another key's");
    let mut longer = grant;
    longer.body.valid_until_utc += 1;
    assert!(!accept(longer, &device, CID), "longer than asked");
    assert!(!format!("{:?}", presented(&issued(&record, HOUR_S))).contains("mac"));
}
