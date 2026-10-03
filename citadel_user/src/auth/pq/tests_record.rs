//! The record's rules: a policy can never be left unsatisfiable, and a code signs in once.

use super::kem::{FactorKeypair, FactorSeed, SEED_LEN};
use super::record::NewFactor;
use super::tests::register;
use citadel_io::{tokio, ErrorCode};
use citadel_types::auth::{FactorKind, SignInPolicy};

fn key(n: u8) -> NewFactor {
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
    let (mut record, _) = register("pw").await;
    assert!(refused_by_policy(record.remove(1)), "the only password");
    assert_eq!(record.usable(FactorKind::Password).count(), 1);
}

#[citadel_io::tokio::test]
async fn a_factor_the_policy_needs_cannot_be_removed_but_a_spare_can() {
    let (mut record, _) = register("pw").await;
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
    let (mut record, _) = register("pw").await;
    assert!(refused_by_policy(record.set_policy(SignInPolicy::KeyOnly)));
    assert!(refused_by_policy(
        record.set_policy(SignInPolicy::PasswordAndKey)
    ));
    assert_eq!(record.policy, SignInPolicy::Password);
}

#[citadel_io::tokio::test]
async fn recovery_codes_are_replaced_not_removed_and_consumed_once() {
    let (mut record, _) = register("pw").await;
    let code = record.usable(FactorKind::RecoveryCode).next().unwrap().id;
    assert!(refused_by_policy(record.remove(code)));
    record.record_use(&[code], 9).unwrap();
    assert!(record.factor(code).unwrap().consumed);
    let again = record.record_use(&[code], 10);
    assert!(matches!(again, Err(err) if err.code == ErrorCode::PqSignInFailed));
    assert_eq!(record.usable(FactorKind::RecoveryCode).count(), 9);

    let fresh = (0..10).map(|n| key(100 + n).ek).collect();
    record.replace_recovery_codes(fresh, 11);
    assert_eq!(record.usable(FactorKind::RecoveryCode).count(), 10);
    assert!(record.factor(code).is_none(), "ids are never reused");
}
