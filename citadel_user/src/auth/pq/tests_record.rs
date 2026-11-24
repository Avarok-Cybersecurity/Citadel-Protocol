//! The record's rules: a policy can never be left unsatisfiable, and the recovery phrase is
//! replaced, never removed.

use super::kem::{FactorKeypair, FactorSeed, SEED_LEN};
use super::record::NewFactor;
use super::tests::register;
use citadel_io::{tokio, ErrorCode};
use citadel_types::auth::{FactorKind, SignInPolicy};

pub(crate) fn key(n: u8) -> NewFactor {
    let ek = FactorKeypair::derive(&FactorSeed::new([n; SEED_LEN]))
        .unwrap()
        .encapsulation_key()
        .clone();
    NewFactor {
        kind: FactorKind::SecurityKey,
        ek,
        credential_id: Some(vec![n]),
        label: format!("key {n}"),
    }
}

fn refused_by_policy<T: std::fmt::Debug>(result: Result<T, citadel_io::NetworkError>) -> bool {
    matches!(result, Err(err) if err.code == ErrorCode::PqSignInPolicy)
}

#[citadel_io::tokio::test]
async fn removing_the_last_factor_is_refused() {
    let mut record = register("pw").await;
    assert!(refused_by_policy(record.remove(1)), "the only password");
    assert_eq!(record.usable(FactorKind::Password).count(), 1);
}

#[citadel_io::tokio::test]
async fn a_factor_the_policy_needs_cannot_be_removed_but_a_spare_can() {
    let mut record = register("pw").await;
    let first = record.add(key(1), 2);
    let second = record.add(key(2), 3);
    record.set_policy(SignInPolicy::KeyOnly).unwrap();
    record.remove(first).unwrap();
    assert!(
        refused_by_policy(record.remove(second)),
        "the last key of a key-only account"
    );
    // The password is not needed by a key-only account, so it may go.
    record.remove(1).unwrap();
    assert!(refused_by_policy(record.set_policy(SignInPolicy::Password)));
}

#[citadel_io::tokio::test]
async fn a_policy_needing_absent_factors_is_refused() {
    let mut record = register("pw").await;
    assert!(refused_by_policy(record.set_policy(SignInPolicy::KeyOnly)));
    assert!(refused_by_policy(
        record.set_policy(SignInPolicy::PasswordAndKey)
    ));
    assert_eq!(record.policy, SignInPolicy::Password);
}

#[citadel_io::tokio::test]
async fn the_recovery_phrase_is_replaced_not_removed_and_not_consumed() {
    let mut record = register("pw").await;
    record.replace_recovery_phrase(key(100).ek, 8);
    let phrase = record.usable(FactorKind::RecoveryPhrase).next().unwrap().id;
    assert!(refused_by_policy(record.remove(phrase)));
    record.record_use(&[phrase], 9).unwrap();
    record.record_use(&[phrase], 10).unwrap();
    assert!(!record.factor(phrase).unwrap().consumed);

    record.replace_recovery_phrase(key(101).ek, 11);
    assert_eq!(record.usable(FactorKind::RecoveryPhrase).count(), 1);
    assert!(record.factor(phrase).is_none(), "ids are never reused");
}
