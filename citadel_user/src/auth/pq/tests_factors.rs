//! Security keys and policies, end to end through the client and server functions.

use super::client::{ClientLogin, SecurityKeyAnswer};
use super::kem::FactorKeypair;
use super::record::{NewFactor, PqAuthRecord};
use super::seed::{security_key_seed, PrfOutput};
use super::tests::{begin, complete, complete_with_key, is_generic_failure, register};
use citadel_io::tokio;
use citadel_types::auth::{FactorKind, SessionScope, SignInPolicy};

const CRED: &[u8] = b"yubikey-credential-id";

fn touch(prf: u8) -> SecurityKeyAnswer {
    SecurityKeyAnswer {
        credential_id: CRED.to_vec(),
        prf: PrfOutput::new([prf; 32]),
    }
}

/// Alice's record with a security key (PRF output `[7; 32]`) and `policy`.
async fn with_key(policy: SignInPolicy) -> PqAuthRecord {
    let (mut record, _) = register("correct horse").await;
    let seed = security_key_seed(&PrfOutput::new([7u8; 32]), CRED);
    let ek = FactorKeypair::derive(&seed)
        .unwrap()
        .encapsulation_key()
        .clone();
    let key = NewFactor {
        kind: FactorKind::SecurityKey,
        ek,
        credential_id: Some(CRED.to_vec()),
        label: "YubiKey".into(),
    };
    let _ = record.add(key, 1_500);
    record.set_policy(policy).unwrap();
    record
}

#[citadel_io::tokio::test]
async fn password_and_key_needs_both() {
    let record = with_key(SignInPolicy::PasswordAndKey).await;
    let both = begin(Some(&record), "alice", Some("correct horse"), None);
    let request = ClientLogin::security_key_request(&both.challenge).unwrap();
    assert_eq!(request.credential_ids, vec![CRED.to_vec()]);
    assert_eq!(request.prf_eval_salt, record.prf_eval_salt);
    let verified = complete_with_key(both, Some(touch(7))).await.unwrap();
    assert_eq!(verified.scope, SessionScope::Full);
    assert_eq!(verified.used.len(), 2);

    let password_only = begin(Some(&record), "alice", Some("correct horse"), None);
    assert!(is_generic_failure(&complete(password_only).await));
    let key_only = begin(Some(&record), "alice", None, None);
    assert!(is_generic_failure(
        &complete_with_key(key_only, Some(touch(7))).await
    ));
}

#[citadel_io::tokio::test]
async fn the_wrong_key_is_refused() {
    let record = with_key(SignInPolicy::PasswordAndKey).await;
    let x = begin(Some(&record), "alice", Some("correct horse"), None);
    // The same credential id, but another authenticator's PRF output.
    assert!(is_generic_failure(
        &complete_with_key(x, Some(touch(8))).await
    ));
}

#[citadel_io::tokio::test]
async fn key_only_signs_in_without_a_password_and_ignores_one() {
    let record = with_key(SignInPolicy::KeyOnly).await;
    let x = begin(Some(&record), "alice", None, None);
    assert_eq!(
        complete_with_key(x, Some(touch(7))).await.unwrap().scope,
        SessionScope::Full
    );

    let password = begin(Some(&record), "alice", Some("correct horse"), None);
    assert!(
        ClientLogin::security_key_request(&password.challenge).is_some(),
        "a key-only account challenges its keys"
    );
    assert!(complete(password).await.is_err());
}
