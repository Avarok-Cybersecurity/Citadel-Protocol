//! Management with a 0.12.2 peer, end to end through the client and server functions: a server
//! answers a 0.12.2 client in 0.12.2's layout and enrols the key that client created before the
//! exchange, a current client changes its factors at a server answering in that layout, and
//! neither side accepts a message from the other layout.

use super::client::{ClientLogin, ClientManagement, ClientProof, RelyingParty};
use super::kem::FactorKeypair;
use super::management_transcript;
use super::messages::{
    key_binding, transcript_bytes, CommitCeremony, LoginProof, ManagementBegin, ManagementCommit,
    ManagementOp, ServerOutcome, SignInLayout,
};
use super::proof::{factor_tag, TranscriptHash, TranscriptPurpose, ENROL_LABEL};
use super::seed::{security_key_seed, PrfOutput};
use super::server::{begin_management, CommitStep};
use super::tests::{password, register, settings, settings_without_keys, CID};
use citadel_io::{tokio, ErrorCode};
use citadel_types::auth::{FactorKind, SessionScope, SignInManagementOp};

const CRED: &[u8] = b"created-by-the-application";
const OLD: SignInLayout = SignInLayout::V0_12_2;
const CEREMONY: SignInLayout = SignInLayout::SecurityKeyCeremony;

/// A 0.12.2 client's `Begin` for a key its application created beforehand.
fn add_created(step_up: super::messages::LoginStart) -> ManagementBegin {
    ManagementBegin {
        op: ManagementOp::AddCreatedSecurityKey {
            credential_id: CRED.to_vec(),
            label: "YubiKey".into(),
        },
        step_up,
        recovery_eks: Vec::new(),
    }
}

/// The 0.12.2 server named no relying party, so its application picked one; this server enrols
/// that key whether or not it names one itself, exactly as 0.12.2 did.
#[citadel_io::tokio::test]
async fn a_0_12_2_client_enrols_the_key_it_created() {
    let (mut record, _) = register("pw").await;
    let (step_up, login) = ClientLogin::start("alice", Some(&password("pw")), None).unwrap();
    let begin = add_created(step_up);
    let (challenge, pending) = begin_management(
        &settings_without_keys(),
        CID,
        &record,
        SessionScope::Full,
        begin.clone(),
        OLD,
    )
    .unwrap();
    assert_eq!(
        challenge.ceremony, None,
        "a 0.12.2 client reads no ceremony"
    );

    let key = FactorKeypair::derive(&security_key_seed(&PrfOutput::new([4; 32]), CRED)).unwrap();
    let new_key_ek = Some(key.encapsulation_key().clone());
    let transcript =
        management_transcript(CID, &begin, &challenge, &key_binding(&new_key_ek, None));
    let ClientProof::Factors {
        proof: LoginProof::Factors(step_up),
        ..
    } = login
        .respond(&challenge.step_up, &transcript, None)
        .await
        .unwrap()
    else {
        panic!("a password step-up")
    };
    let commit = ManagementCommit {
        step_up,
        new_key_ek,
        ceremony: None,
    };
    let CommitStep::Enrol(enrol, pending) = pending.commit(&commit).unwrap() else {
        panic!("adding a key must ask for its proof")
    };
    let enrol_transcript = TranscriptHash::new(
        TranscriptPurpose::StepUp,
        CID,
        &[transcript.as_bytes(), &transcript_bytes(&enrol)],
    );
    let k = key.decapsulate(&enrol.ct).unwrap();
    let proof = super::messages::EnrolProof {
        tag: factor_tag(&k, ENROL_LABEL, 0, &enrol_transcript),
    };
    let added = pending
        .finish(&proof)
        .unwrap()
        .apply(&mut record, 3)
        .unwrap();
    assert!(matches!(added, ServerOutcome::Added { .. }));
    let enrolled: Vec<_> = record
        .usable(FactorKind::SecurityKey)
        .map(|f| f.credential_id.clone())
        .collect();
    assert_eq!(enrolled, vec![Some(CRED.to_vec())]);
}

/// A current client at a server answering in 0.12.2's layout: the commit carries nothing
/// appended, and the key request names no relying party, as 0.12.2's did.
#[citadel_io::tokio::test]
async fn a_current_client_changes_its_factors_in_the_0_12_2_layout() {
    let (mut record, _) = register("pw").await;
    let list = SignInManagementOp::ListCredentials;
    let (begin, client) = ClientManagement::begin("alice", list, Some(&password("pw"))).unwrap();
    let (challenge, pending) =
        begin_management(&settings(), CID, &record, SessionScope::Full, begin, OLD).unwrap();
    assert_eq!(challenge.ceremony, None);
    assert_eq!(
        RelyingParty::of_management(&challenge),
        RelyingParty::Unnamed
    );
    let (commit, _) = client.commit(CID, &challenge, None, None).await.unwrap();
    assert_eq!(
        commit.ceremony, None,
        "nothing appended for a 0.12.2 server"
    );
    let CommitStep::Ready(change) = pending.commit(&commit).unwrap() else {
        panic!("a list needs no proof of possession")
    };
    assert!(matches!(
        change.apply(&mut record, 3).unwrap(),
        ServerOutcome::Credentials { .. }
    ));
}

#[citadel_io::tokio::test]
async fn an_enrolment_from_the_other_layout_is_refused() {
    let (record, _) = register("pw").await;
    let (step_up, _) = ClientLogin::start("alice", Some(&password("pw")), None).unwrap();
    let created = begin_management(
        &settings(),
        CID,
        &record,
        SessionScope::Full,
        add_created(step_up),
        CEREMONY,
    );
    assert_eq!(
        created.err().map(|e| e.code),
        Some(ErrorCode::PqSignInMalformed)
    );
    let add = SignInManagementOp::AddSecurityKey {
        label: "YubiKey".into(),
    };
    let (begin, _) = ClientManagement::begin("alice", add, Some(&password("pw"))).unwrap();
    let by_ceremony = begin_management(&settings(), CID, &record, SessionScope::Full, begin, OLD);
    assert_eq!(
        by_ceremony.err().map(|e| e.code),
        Some(ErrorCode::PqSignInMalformed)
    );
}

#[citadel_io::tokio::test]
async fn a_commit_in_the_other_layout_than_its_challenge_is_refused() {
    let (record, _) = register("pw").await;
    let list = SignInManagementOp::ListCredentials;
    let (begin, client) = ClientManagement::begin("alice", list, Some(&password("pw"))).unwrap();
    let (challenge, pending) =
        begin_management(&settings(), CID, &record, SessionScope::Full, begin, OLD).unwrap();
    let (mut commit, _) = client.commit(CID, &challenge, None, None).await.unwrap();
    commit.ceremony = Some(CommitCeremony { new_key: None });
    let refused = pending.commit(&commit).err().map(|e| e.code);
    assert_eq!(refused, Some(ErrorCode::PqSignInMalformed));
}

#[test]
fn a_0_12_2_servers_key_challenge_names_no_relying_party() {
    use super::kem::KemCiphertext;
    use super::messages::{ChallengeBody, FactorChallenge, FactorChallenges, LoginChallenge};
    use super::record::KsfParams;
    let challenge = LoginChallenge {
        server_nonce: [0; 32],
        body: ChallengeBody::Factors(FactorChallenges {
            oprf_evaluated: None,
            salt_user: [0; 32],
            prf_eval_salt: [6; 32],
            ksf: KsfParams::FLOOR,
            challenges: vec![FactorChallenge {
                factor_id: 2,
                kind: FactorKind::SecurityKey,
                credential_id: Some(CRED.to_vec()),
                ct: KemCiphertext::try_from(vec![0; 1568]).unwrap(),
            }],
        }),
    };
    let request = ClientLogin::security_key_request(&challenge, RelyingParty::Unnamed)
        .unwrap()
        .expect("a key is challenged");
    assert_eq!(request.rp_id, None);
    let refused = ClientLogin::security_key_request(&challenge, RelyingParty::Named(None));
    assert_eq!(
        refused.err().map(|e| e.code),
        Some(ErrorCode::PqSignInUnavailable)
    );
}
