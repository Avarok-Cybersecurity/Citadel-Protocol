//! A new account is given the recovery phrase, and the phrase signs it in.

use super::client::{ClientRegistration, NewRecovery, RecoveryOffer};
use super::kem::{EncapsulationKey, FactorKeypair, FactorSeed, SEED_LEN};
use super::messages::RegFinish;
use super::phrase::RecoveryPhrase;
use super::record::PqAuthRecord;
use super::server::registration_reply;
use super::tests::{password, settings};
use super::tests_recovery::{sign_in, DOMAIN};
use crate::serialization::SyncIO;
use citadel_io::{tokio, ErrorCode};
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
async fn an_account_given_no_domain_or_upgrading_gets_no_recovery_credential() {
    let (record, issued) = register(NewRecovery::None).await;
    assert!(issued.phrase.is_none());
    assert_eq!(kinds(&record), [FactorKind::Password]);
}

/// The 0.12.3 shape of `RegFinish`: a key per recovery code, and no phrase.
#[derive(serde::Serialize, serde::Deserialize)]
struct RegFinishOf0123 {
    password_ek: EncapsulationKey,
    recovery_eks: Vec<EncapsulationKey>,
}

/// A registration that brings recovery codes is an older client's, and does not read; a current
/// one does, with or without a phrase.
#[tokio::test]
async fn a_registration_with_recovery_codes_is_refused() {
    let ek = |seed: u8| {
        FactorKeypair::derive(&FactorSeed::new([seed; SEED_LEN]))
            .unwrap()
            .encapsulation_key()
            .clone()
    };
    let older = RegFinishOf0123 {
        password_ek: ek(1),
        recovery_eks: (2..12).map(ek).collect(),
    };
    let refused = RegFinish::deserialize_from_vector(&older.serialize_to_vector().unwrap());
    assert_eq!(refused.unwrap_err().code, ErrorCode::DeserializationFailed);

    for recovery_phrase_ek in [None, Some(ek(2))] {
        let current = RegFinish {
            password_ek: ek(1),
            recovery_phrase_ek,
        };
        let read = RegFinish::deserialize_from_vector(&current.serialize_to_vector().unwrap());
        assert_eq!(read.unwrap(), current);
    }
}
