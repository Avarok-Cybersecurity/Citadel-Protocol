//! The credential changes recovery exists for: a forgotten password, a changed one, a new phrase.

use super::messages::ServerOutcome;
use super::tests::register;
use super::tests_recovery::*;
use citadel_io::{tokio, ErrorCode};
use citadel_types::auth::{FactorKind, SessionScope, SignInManagementOp};

/// Control: make `set_password` add a factor instead of replacing the one there, and the
/// factor-count and old-password assertions go red.
#[tokio::test]
async fn a_recovery_session_sets_a_forgotten_password() {
    let mut record = register("pw").await;
    let before = record.clone();
    let set = manage(
        &mut record,
        SessionScope::Recovery,
        SignInManagementOp::SetPassword,
        None,
        Some("new password"),
    );
    assert_eq!(set.await.unwrap().0, ServerOutcome::PasswordSet);
    let passwords: Vec<_> = record.usable(FactorKind::Password).collect();
    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0].id, 1, "the password keeps its id");
    assert_ne!(
        passwords[0].ek,
        before.usable(FactorKind::Password).next().unwrap().ek
    );
    assert_ne!(record.salt_user, before.salt_user);
    assert_eq!(record.prf_eval_salt, before.prf_eval_salt);
    assert_eq!(record.factors().len(), before.factors().len());
    assert!(failed(sign_in(&record, Some("pw"), None).await));
    let full = sign_in(&record, Some("new password"), None).await.unwrap();
    assert_eq!(full.scope, SessionScope::Full);
}

#[tokio::test]
async fn a_full_session_changes_the_password_only_with_the_current_one() {
    let mut record = register("pw").await;
    let op = || SignInManagementOp::SetPassword;
    let wrong = manage(
        &mut record,
        SessionScope::Full,
        op(),
        Some("nope"),
        Some("pw2"),
    )
    .await;
    assert_eq!(wrong.err().map(|e| e.code), Some(ErrorCode::PqSignInFailed));
    let missing = manage(&mut record, SessionScope::Full, op(), Some("pw"), None).await;
    assert_eq!(
        missing.err().map(|e| e.code),
        Some(ErrorCode::PqSignInFactorMissing)
    );
    let set = manage(
        &mut record,
        SessionScope::Full,
        op(),
        Some("pw"),
        Some("pw2"),
    )
    .await;
    assert_eq!(set.unwrap().0, ServerOutcome::PasswordSet);
    assert!(sign_in(&record, Some("pw2"), None).await.is_ok());
}

#[tokio::test]
async fn a_recovery_session_replaces_the_phrase() {
    let mut record = register("pw").await;
    let old = phrase_of(&with_phrase(&mut record).await, DOMAIN);
    let op = SignInManagementOp::RegenerateRecoveryPhrase {
        canonical_domain: DOMAIN.into(),
    };
    let (outcome, committed) = manage(&mut record, SessionScope::Recovery, op, None, None)
        .await
        .unwrap();
    assert_eq!(outcome, ServerOutcome::RecoveryPhraseReplaced);
    let new = phrase_of(&committed.into_recovery_phrase().unwrap(), DOMAIN);
    assert!(failed(recover(Some(&record), "alice", &old).await));
    assert!(recover(Some(&record), "alice", &new).await.is_ok());
}
