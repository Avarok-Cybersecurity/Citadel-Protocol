//! The whole exchange, client and server functions back to back, with no transport in between.

use super::client::{ClientLogin, ClientProof, ClientRegistration, SecurityKeyAnswer};
use super::login_transcript;
use super::messages::{ChallengeBody, LoginChallenge, LoginProof, LoginStart};
use super::oprf::OprfSeed;
use super::record::{KsfParams, PqAuthRecord};
use super::recovery::RecoveryCode;
use super::server::{
    build_login_challenge, registration_reply, AccountAuth, Expected, PqAuthServerSettings,
    VerifiedLogin,
};
use citadel_io::tokio;
use citadel_io::ErrorCode;
use citadel_types::auth::SessionScope;
use citadel_types::crypto::SecBuffer;

pub(crate) const CID: u64 = 0x0C1D_ADE1;

pub(crate) fn settings() -> PqAuthServerSettings {
    PqAuthServerSettings::new(OprfSeed::from_bytes([42u8; 32]), KsfParams::FLOOR).unwrap()
}

pub(crate) fn password(text: &str) -> SecBuffer {
    SecBuffer::from(text.as_bytes().to_vec())
}

/// Registers `alice` with `pw`; returns her record and recovery codes.
pub(crate) async fn register(pw: &str) -> (PqAuthRecord, Vec<RecoveryCode>) {
    let s = settings();
    let (start, client) = ClientRegistration::start("alice", &password(pw)).unwrap();
    let (reply, pending) = registration_reply(&s, &start).unwrap();
    let (finish, codes) = client.finish(&reply, true).await.unwrap();
    (pending.finish(finish, 1_000).unwrap(), codes)
}

/// One login's messages, so a test can tamper with any of them.
pub(crate) struct Exchange {
    pub start: LoginStart,
    pub challenge: LoginChallenge,
    pub client: ClientLogin,
    pub expected: Expected,
}

pub(crate) fn begin(
    record: Option<&PqAuthRecord>,
    username: &str,
    pw: Option<&str>,
    code: Option<&RecoveryCode>,
) -> Exchange {
    let pw = pw.map(password);
    let (start, client) = ClientLogin::start(username, pw.as_ref(), code).unwrap();
    let account = record.map_or(AccountAuth::Unknown, AccountAuth::PostQuantum);
    let (challenge, expected) = build_login_challenge(&settings(), account, &start).unwrap();
    Exchange {
        start,
        challenge,
        client,
        expected,
    }
}

/// The client answers, and the server verifies against the challenge it really issued.
pub(crate) async fn complete(x: Exchange) -> Result<VerifiedLogin, citadel_io::NetworkError> {
    complete_with_key(x, None).await
}

pub(crate) async fn complete_with_key(
    x: Exchange,
    key: Option<SecurityKeyAnswer>,
) -> Result<VerifiedLogin, citadel_io::NetworkError> {
    let server_transcript = login_transcript(CID, &x.start, &x.challenge);
    let expected = x.expected;
    let proof = x
        .client
        .respond(&x.challenge, &server_transcript, key)
        .await?;
    let ClientProof {
        proof: LoginProof::Factors(finish),
        ..
    } = proof;
    expected.bind(server_transcript).verify(&finish)
}

pub(crate) fn is_generic_failure(result: &Result<VerifiedLogin, citadel_io::NetworkError>) -> bool {
    matches!(result, Err(err) if err.code == ErrorCode::PqSignInFailed)
}

#[citadel_io::tokio::test]
async fn the_right_password_signs_in_with_a_full_session() {
    let (record, _) = register("correct horse").await;
    let verified = complete(begin(Some(&record), "alice", Some("correct horse"), None))
        .await
        .unwrap();
    assert_eq!(verified.scope, SessionScope::Full);
    assert_eq!(verified.used, vec![1]);
}

#[citadel_io::tokio::test]
async fn a_wrong_password_is_refused() {
    let (record, _) = register("correct horse").await;
    let result = complete(begin(Some(&record), "alice", Some("battery staple"), None)).await;
    assert!(is_generic_failure(&result));
}

#[citadel_io::tokio::test]
async fn a_tag_replayed_from_another_transcript_is_refused() {
    let (record, _) = register("correct horse").await;
    let x = begin(Some(&record), "alice", Some("correct horse"), None);
    let expected = x.expected;
    // The client's tags are bound to a transcript other than the one the server issued.
    let mut other = x.challenge.clone();
    other.server_nonce[0] ^= 1;
    let elsewhere = login_transcript(CID, &x.start, &other);
    let ClientProof {
        proof: LoginProof::Factors(finish),
        ..
    } = x
        .client
        .respond(&x.challenge, &elsewhere, None)
        .await
        .unwrap();
    let server_transcript = login_transcript(CID, &x.start, &x.challenge);
    assert!(is_generic_failure(
        &expected.bind(server_transcript).verify(&finish)
    ));
}

#[citadel_io::tokio::test]
async fn a_tampered_ciphertext_is_refused() {
    let (record, _) = register("correct horse").await;
    let mut x = begin(Some(&record), "alice", Some("correct horse"), None);
    let ChallengeBody::Factors(factors) = &mut x.challenge.body;
    let mut ct: Vec<u8> = factors.challenges[0].ct.clone().into();
    ct[100] ^= 0x01;
    factors.challenges[0].ct = ct.try_into().unwrap();
    assert!(is_generic_failure(&complete(x).await));
}

#[citadel_io::tokio::test]
async fn a_tampered_oprf_evaluation_is_refused() {
    let (record, _) = register("correct horse").await;
    let mut x = begin(Some(&record), "alice", Some("correct horse"), None);
    // A valid group element, but the evaluation under another user's key.
    let forged = begin(Some(&record), "mallory", Some("correct horse"), None);
    let (ChallengeBody::Factors(real), ChallengeBody::Factors(fake)) =
        (&mut x.challenge.body, &forged.challenge.body);
    assert_ne!(real.oprf_evaluated, fake.oprf_evaluated);
    real.oprf_evaluated = fake.oprf_evaluated.clone();
    assert!(is_generic_failure(&complete(x).await));
}

#[citadel_io::tokio::test]
async fn a_recovery_code_signs_in_once_to_a_recovery_session() {
    let (mut record, codes) = register("correct horse").await;
    let verified = complete(begin(Some(&record), "alice", None, Some(&codes[3])))
        .await
        .unwrap();
    assert_eq!(verified.scope, SessionScope::Recovery);
    record.record_use(&verified.used, 2_000).unwrap();

    let again = complete(begin(Some(&record), "alice", None, Some(&codes[3]))).await;
    assert!(
        is_generic_failure(&again),
        "a used code must not sign in again"
    );
    let other = complete(begin(Some(&record), "alice", None, Some(&codes[4]))).await;
    assert_eq!(other.unwrap().scope, SessionScope::Recovery);
}
