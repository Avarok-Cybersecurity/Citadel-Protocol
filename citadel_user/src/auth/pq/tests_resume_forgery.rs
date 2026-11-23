//! A grant the server did not issue as presented, or presented without the key it names, is an
//! ordinary failed sign-in: it is never told it is expired or revoked.

use super::client::{ClientLogin, ClientProof};
use super::login_transcript;
use super::messages::LoginProof;
use super::resume::{DeviceKey, PresentedResume, ResumePolicy};
use super::server::{build_resume_challenge, AccountAuth, PqAuthServerSettings};
use super::tests::{register, sent, settings, CID};
use super::tests_resume::{
    issued, presented, refusal, resume, resuming, start_with, DAY, HOUR_MS, HOUR_S, NOW,
};
use citadel_io::{tokio, ErrorCode};

/// Control: return `true` from `ResumeGrant::authentic`.
#[tokio::test]
async fn a_forged_or_altered_grant_is_an_ordinary_failed_sign_in() {
    let record = register("pw").await;
    let credential = issued(&record, HOUR_S);
    let genuine = presented(&credential);
    assert_eq!(refusal(DAY, &record, genuine.clone(), NOW + 1), None);
    let failed = Some(ErrorCode::PqSignInFailed);
    let altered = |alter: &dyn Fn(&mut PresentedResume)| {
        let mut forged = genuine.clone();
        alter(&mut forged);
        // Past the genuine expiry too: a forgery is never told it is expired.
        [NOW + 1, NOW + 2 * HOUR_MS].map(|now| refusal(DAY, &record, forged.clone(), now))
    };

    assert_eq!(altered(&|p| p.grant.body.valid_until_utc += 1), [failed; 2]);
    assert_eq!(altered(&|p| p.grant.body.issued_at_utc += 1), [failed; 2]);
    assert_eq!(altered(&|p| p.grant.body.cid ^= 1), [failed; 2]);
    assert_eq!(altered(&|p| p.grant.body.version += 1), [failed; 2]);
    assert_eq!(altered(&|p| p.grant.body.state_hash[0] ^= 1), [failed; 2]);
    assert_eq!(altered(&|p| p.grant.body.device_fpr[0] ^= 1), [failed; 2]);
    assert_eq!(altered(&|p| p.grant.mac[31] ^= 1), [failed; 2]);

    // Another device's key under this grant, and this grant on another account's session.
    let other_device = DeviceKey::generate().request(HOUR_S).unwrap().device_ek;
    assert_eq!(
        altered(&|p| p.device_ek = other_device.clone()),
        [failed; 2]
    );
    let account = AccountAuth::PostQuantum(&record);
    let start = start_with(genuine.clone());
    let elsewhere = build_resume_challenge(&resuming(DAY), CID + 1, account, &start, NOW + 1);
    assert_eq!(elsewhere.err().unwrap().code, ErrorCode::PqSignInFailed);

    // Another tenant's seed, a server that honours none, and an account with no record.
    let other_tenant = PqAuthServerSettings::new(
        super::oprf::OprfSeed::from_bytes([7; 32]),
        super::record::KsfParams::FLOOR,
        super::throttle::ThrottlePolicy::RECOMMENDED,
    );
    let other_tenant = other_tenant
        .unwrap()
        .with_resume(ResumePolicy::new(DAY).unwrap());
    let account = || AccountAuth::PostQuantum(&record);
    for (server, account) in [
        (other_tenant, account()),
        (settings(), account()),
        (resuming(DAY), AccountAuth::Unknown),
        (resuming(DAY), AccountAuth::Legacy),
    ] {
        let refused = build_resume_challenge(&server, CID, account, &start, NOW + 1);
        assert_eq!(refused.err().unwrap().code, ErrorCode::PqSignInFailed);
    }
}

/// Control: drop the fingerprint comparison in `check`; accept any tag for `Rule::Resume`.
#[tokio::test]
async fn a_grant_without_its_device_key_cannot_resume() {
    let record = register("pw").await;
    let credential = issued(&record, HOUR_S);
    assert!(resume(&record, &credential, NOW + 1).await.is_ok());

    // The grant, copied, with a key the thief drew: the fingerprint does not match.
    let thief = DeviceKey::generate();
    let mut copied = presented(&credential);
    copied.device_ek = thief.request(HOUR_S).unwrap().device_ek;
    assert_eq!(
        refusal(DAY, &record, copied, NOW + 1),
        Some(ErrorCode::PqSignInFailed)
    );

    // The grant and the device's public key, copied: the challenge cannot be answered.
    let start = start_with(presented(&credential));
    let account = AccountAuth::PostQuantum(&record);
    let (challenge, expected) =
        build_resume_challenge(&resuming(DAY), CID, account, &start, NOW + 1).unwrap();
    let transcript = login_transcript(CID, &start, &sent(&challenge));
    let stolen = issued(&record, HOUR_S);
    let (_, thief) = ClientLogin::start_resume("alice", &stolen, NOW + 1).unwrap();
    let ClientProof::Factors {
        proof: LoginProof::Factors(finish),
        ..
    } = thief.respond(&challenge, &transcript, None).await.unwrap()
    else {
        panic!("not a factor proof");
    };
    let refused = expected.bind(transcript).verify(&finish);
    assert_eq!(refused.err().unwrap().code, ErrorCode::PqSignInFailed);
}
