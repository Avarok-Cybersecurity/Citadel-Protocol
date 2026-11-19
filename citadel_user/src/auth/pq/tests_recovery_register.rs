//! A new account is given the recovery phrase, not codes, and the phrase signs it in.

use super::client::{ClientRegistration, NewRecovery, RecoveryOffer};
use super::kem::FactorKeypair;
use super::phrase::RecoveryPhrase;
use super::record::PqAuthRecord;
use super::recovery::RecoveryCode;
use super::server::registration_reply;
use super::tests::{password, settings};
use super::tests_recovery::{sign_in, DOMAIN};
use citadel_io::tokio;
use citadel_types::auth::{FactorKind, SessionScope};

async fn register(recovery: NewRecovery<'_>) -> (PqAuthRecord, super::client::IssuedRecovery) {
    let (start, client) = ClientRegistration::start("alice", &password("pw")).unwrap();
    let (reply, pending) = registration_reply(&settings(), &start).unwrap();
    let (finish, issued) = client.finish(&reply, recovery).await.unwrap();
    (pending.finish(finish, 1_000).unwrap(), issued)
}

fn kinds(record: &PqAuthRecord) -> Vec<FactorKind> {
    record.factors().iter().map(|f| f.kind).collect()
}

fn phrase_for(domain: &str) -> NewRecovery<'_> {
    NewRecovery::Phrase {
        username: "alice",
        canonical_domain: domain,
    }
}

/// Control: have `PendingRegistration::finish` ignore `recovery_phrase_ek` and the account has
/// no recovery factor.
#[tokio::test]
async fn a_new_account_gets_a_phrase_and_no_codes() {
    let (record, issued) = register(phrase_for(DOMAIN)).await;
    assert!(issued.codes.is_empty());
    let seed = issued.phrase.expect("a phrase was drawn");
    assert_eq!(
        kinds(&record),
        [FactorKind::Password, FactorKind::RecoveryPhrase]
    );

    let phrase = RecoveryPhrase::new(seed, DOMAIN).unwrap();
    let verified = sign_in(&record, None, Some(RecoveryOffer::Phrase(&phrase))).await;
    assert_eq!(verified.unwrap().scope, SessionScope::Recovery);
    let elsewhere = RecoveryPhrase::new(phrase.seed().clone(), "example.org").unwrap();
    let refused = sign_in(&record, None, Some(RecoveryOffer::Phrase(&elsewhere))).await;
    assert!(
        refused.is_err(),
        "the phrase is bound to the domain it was issued for"
    );
}

#[tokio::test]
async fn an_older_server_still_gets_codes_and_an_upgrade_gets_nothing() {
    let (record, issued) = register(NewRecovery::Codes).await;
    assert_eq!(issued.codes.len(), 10);
    assert!(issued.phrase.is_none());
    let codes = kinds(&record)
        .iter()
        .filter(|k| **k == FactorKind::RecoveryCode)
        .count();
    assert_eq!(codes, 10);

    let (record, issued) = register(NewRecovery::None).await;
    assert!(issued.codes.is_empty() && issued.phrase.is_none());
    assert_eq!(kinds(&record), [FactorKind::Password]);
}

#[tokio::test]
async fn a_registration_with_both_a_phrase_and_codes_is_refused() {
    let (start, client) = ClientRegistration::start("alice", &password("pw")).unwrap();
    let (reply, pending) = registration_reply(&settings(), &start).unwrap();
    let (mut finish, _) = client.finish(&reply, phrase_for(DOMAIN)).await.unwrap();
    for code in RecoveryCode::generate_set() {
        let keypair = FactorKeypair::derive(&super::seed::recovery_seed(&code)).unwrap();
        finish
            .recovery_eks
            .push(keypair.encapsulation_key().clone());
    }
    assert!(pending.finish(finish, 1_000).is_err());
}
