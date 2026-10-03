//! Management end to end through the client and server functions: a step-up bound to its change,
//! a proof of possession for a new key, and the recovery session's limits.

use super::client::ClientManagement;
use super::kem::{FactorKeypair, FactorSeed, SEED_LEN};
use super::management_transcript;
use super::messages::{ManagementBegin, ServerOutcome};
use super::record::PqAuthRecord;
use super::seed::PrfOutput;
use super::server::{begin_management, CommitStep};
use super::tests::{password, register, settings, CID};
use citadel_io::{tokio, ErrorCode};
use citadel_types::auth::{FactorKind, SessionScope, SignInManagementOp, SignInPolicy};

const CRED: &[u8] = b"new-key";

fn add_key() -> SignInManagementOp {
    SignInManagementOp::AddSecurityKey {
        credential_id: CRED.to_vec(),
        label: "YubiKey".into(),
    }
}

/// Runs one change to the end; `prf` is the new key's PRF output, `step_up` the password.
async fn change(
    record: &mut PqAuthRecord,
    scope: SessionScope,
    op: SignInManagementOp,
    step_up: Option<&str>,
    prf: Option<u8>,
) -> Result<ServerOutcome, citadel_io::NetworkError> {
    let pw = step_up.map(password);
    let (begin, client) = ClientManagement::begin("alice", op, pw.as_ref())?;
    let (challenge, pending) = begin_management(&settings(), CID, record, scope, begin)?;
    let new_key = prf.map(|n| PrfOutput::new([n; 32]));
    let (commit, committed) = client.commit(CID, &challenge, None, new_key).await?;
    let change = match pending.commit(&commit)? {
        CommitStep::Ready(change) => change,
        CommitStep::Enrol(enrol, pending) => {
            pending.finish(&committed.enrol_proof(CID, &enrol)?)?
        }
    };
    change.apply(record, 3)
}

fn code(result: &Result<ServerOutcome, citadel_io::NetworkError>) -> Option<ErrorCode> {
    result.as_ref().err().map(|err| err.code)
}

#[citadel_io::tokio::test]
async fn a_step_up_with_the_password_lists_and_a_wrong_one_is_refused() {
    let (mut record, _) = register("pw").await;
    let listed = change(
        &mut record,
        SessionScope::Full,
        SignInManagementOp::ListCredentials,
        Some("pw"),
        None,
    );
    assert!(matches!(listed.await.unwrap(), ServerOutcome::Credentials(c) if c.len() == 11));
    let wrong = change(
        &mut record,
        SessionScope::Full,
        SignInManagementOp::ListCredentials,
        Some("nope"),
        None,
    );
    assert_eq!(code(&wrong.await), Some(ErrorCode::PqSignInFailed));
}

#[citadel_io::tokio::test]
async fn a_key_is_enrolled_only_with_its_proof() {
    let (mut record, _) = register("pw").await;
    let (begin, client) =
        ClientManagement::begin("alice", add_key(), Some(&password("pw"))).unwrap();
    let (challenge, pending) =
        begin_management(&settings(), CID, &record, SessionScope::Full, begin).unwrap();
    let (commit, committed) = client
        .commit(CID, &challenge, None, Some(PrfOutput::new([5; 32])))
        .await
        .unwrap();
    let CommitStep::Enrol(enrol, pending) = pending.commit(&commit).unwrap() else {
        panic!("adding a key must ask for its proof")
    };
    let mut forged = committed.enrol_proof(CID, &enrol).unwrap();
    forged.tag[0] ^= 1;
    assert!(
        pending.finish(&forged).is_err(),
        "a key enrolled without its proof"
    );

    let added = change(
        &mut record,
        SessionScope::Full,
        add_key(),
        Some("pw"),
        Some(5),
    )
    .await;
    assert!(matches!(added.unwrap(), ServerOutcome::Added { .. }));
    assert_eq!(record.usable(FactorKind::SecurityKey).count(), 1);
    let again = change(
        &mut record,
        SessionScope::Full,
        add_key(),
        Some("pw"),
        Some(5),
    )
    .await;
    assert_eq!(
        code(&again),
        Some(ErrorCode::PqSignInPolicy),
        "the same key twice"
    );
}

#[citadel_io::tokio::test]
async fn a_step_up_is_bound_to_its_change_and_to_the_key_being_added() {
    let (record, _) = register("pw").await;
    let list = SignInManagementOp::ListCredentials;
    let (begin, _) = ClientManagement::begin("alice", list, Some(&password("pw"))).unwrap();
    let (challenge, _) =
        begin_management(&settings(), CID, &record, SessionScope::Full, begin.clone()).unwrap();
    let remove = ManagementBegin {
        op: SignInManagementOp::RemoveCredential { id: 1 },
        ..begin.clone()
    };
    let base = management_transcript(CID, &begin, &challenge, None);
    assert_ne!(base, management_transcript(CID, &remove, &challenge, None));
    let kp = FactorKeypair::derive(&FactorSeed::new([2; SEED_LEN])).unwrap();
    let with_key = management_transcript(CID, &begin, &challenge, Some(kp.encapsulation_key()));
    assert_ne!(base, with_key);
}

#[citadel_io::tokio::test]
async fn removing_the_last_factor_through_management_is_refused() {
    let (mut record, _) = register("pw").await;
    let remove = SignInManagementOp::RemoveCredential { id: 1 };
    let refused = change(&mut record, SessionScope::Full, remove, Some("pw"), None).await;
    assert_eq!(code(&refused), Some(ErrorCode::PqSignInPolicy));
}

#[citadel_io::tokio::test]
async fn a_recovery_session_may_enrol_a_key_and_set_the_policy_and_nothing_else() {
    let (mut record, _) = register("pw").await;
    let list = change(
        &mut record,
        SessionScope::Recovery,
        SignInManagementOp::ListCredentials,
        None,
        None,
    );
    assert_eq!(code(&list.await), Some(ErrorCode::PqSignInRestricted));
    let regen = change(
        &mut record,
        SessionScope::Recovery,
        SignInManagementOp::RegenerateRecoveryCodes,
        None,
        None,
    );
    assert_eq!(code(&regen.await), Some(ErrorCode::PqSignInRestricted));

    let added = change(
        &mut record,
        SessionScope::Recovery,
        add_key(),
        None,
        Some(9),
    )
    .await;
    assert!(matches!(added.unwrap(), ServerOutcome::Added { .. }));
    let key_only = SignInManagementOp::SetSignInPolicy {
        policy: SignInPolicy::KeyOnly,
    };
    let set = change(&mut record, SessionScope::Recovery, key_only, None, None).await;
    assert!(matches!(set.unwrap(), ServerOutcome::PolicySet));
    assert_eq!(record.policy, SignInPolicy::KeyOnly);
}

#[citadel_io::tokio::test]
async fn regenerated_codes_replace_every_old_one() {
    let (mut record, _) = register("pw").await;
    let old: Vec<_> = record
        .usable(FactorKind::RecoveryCode)
        .map(|f| f.id)
        .collect();
    let regen = SignInManagementOp::RegenerateRecoveryCodes;
    let replaced = change(&mut record, SessionScope::Full, regen, Some("pw"), None).await;
    assert!(matches!(
        replaced.unwrap(),
        ServerOutcome::RecoveryCodesReplaced
    ));
    let new: Vec<_> = record
        .usable(FactorKind::RecoveryCode)
        .map(|f| f.id)
        .collect();
    assert_eq!(new.len(), 10);
    assert!(old.iter().all(|id| !new.contains(id)));
}
