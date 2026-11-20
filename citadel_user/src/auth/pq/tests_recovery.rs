//! The recovery phrase end to end through the client and server functions: its factor, the
//! recovery lane's challenge and transcript, and the credential changes a recovery session makes.

use super::client::{ClientCommitted, ClientLogin, ClientManagement, ClientProof, RecoveryOffer};
use super::kem::FactorKeypair;
use super::messages::{
    AuthChallenge, DeviceOffer, LoginFinish, LoginProof, RecoverStart, ServerOutcome,
};
use super::phrase::{RecoveryPhrase, RecoverySeed};
use super::record::PqAuthRecord;
use super::server::{begin_management, build_recovery_challenge, CommitStep, VerifiedLogin};
use super::tests::{password, register, sent, settings, CID};
use super::{channel_binding, recover_transcript};
use citadel_io::{tokio, ErrorCode, NetworkError};
use citadel_types::auth::{FactorKind, SessionScope, SignInManagementOp};

pub(super) const DOMAIN: &str = "example.com";

pub(super) fn ek(phrase: &RecoveryPhrase, username: &str) -> Vec<u8> {
    let keypair: FactorKeypair = phrase.keypair(username).unwrap();
    keypair.encapsulation_key().as_bytes().to_vec()
}

pub(super) fn phrase_of(seed: &RecoverySeed, domain: &str) -> RecoveryPhrase {
    RecoveryPhrase::new(seed.clone(), domain).unwrap()
}

/// One change, run to the end against `record`.
pub(super) async fn manage(
    record: &mut PqAuthRecord,
    scope: SessionScope,
    op: SignInManagementOp,
    step_up: Option<&str>,
    new_password: Option<&str>,
) -> Result<(ServerOutcome, ClientCommitted), NetworkError> {
    let (pw, new) = (step_up.map(password), new_password.map(password));
    let (begin, client) = ClientManagement::begin("alice", op, pw.as_ref(), new.as_ref())?;
    let (challenge, pending) = begin_management(&settings(), CID, record, scope, begin)?;
    let (commit, committed) = client.commit(CID, &challenge, None, None).await?;
    let CommitStep::Ready(change) = pending.commit(&commit)? else {
        panic!("no key is added here")
    };
    Ok((change.apply(record, 7)?, committed))
}

/// Gives `record` a phrase from a full session; returns its seed.
pub(super) async fn with_phrase(record: &mut PqAuthRecord) -> RecoverySeed {
    let op = SignInManagementOp::RegenerateRecoveryPhrase {
        canonical_domain: DOMAIN.into(),
    };
    let (outcome, committed) = manage(record, SessionScope::Full, op, Some("pw"), None)
        .await
        .unwrap();
    assert_eq!(outcome, ServerOutcome::RecoveryPhraseReplaced);
    committed
        .into_recovery_phrase()
        .expect("the client drew a phrase")
}

/// A sign-in that offers `offer` and a password, the connect path's way.
pub(super) async fn sign_in(
    record: &PqAuthRecord,
    pw: Option<&str>,
    offer: Option<RecoveryOffer<'_>>,
) -> Result<VerifiedLogin, NetworkError> {
    super::tests::complete(super::tests::begin_offering(
        Some(record),
        "alice",
        pw,
        offer,
    ))
    .await
}

/// One run of the recovery lane over a key exchange whose binding is `binding`.
pub(super) struct Lane {
    pub start: RecoverStart,
    pub client: ClientLogin,
    pub challenge: AuthChallenge,
    pub expected: super::server::Expected,
}

pub(super) fn lane(record: Option<&PqAuthRecord>, username: &str, phrase: &RecoveryPhrase) -> Lane {
    let offer = Some(RecoveryOffer::Phrase(phrase));
    let (login, client) = ClientLogin::start(username, None, offer).unwrap();
    let device = DeviceOffer {
        label: "laptop".into(),
    };
    let start = RecoverStart { login, device };
    let (challenge, expected) =
        build_recovery_challenge(&settings(), record, &start.login).unwrap();
    Lane {
        start,
        client,
        challenge: sent(&challenge),
        expected,
    }
}

impl Lane {
    pub(super) async fn proof(
        self,
        binding: &[u8; 32],
    ) -> (LoginFinish, super::server::Expected, [u8; 32]) {
        let transcript = recover_transcript(CID, binding, &self.start, &self.challenge);
        let proof = self
            .client
            .respond(&self.challenge.challenge, &transcript, None);
        let finish = match proof.await.unwrap() {
            ClientProof::Factors {
                proof: LoginProof::Factors(finish),
                ..
            } => finish,
            _ => panic!("a recovery proves factors"),
        };
        (finish, self.expected, *binding)
    }
}

pub(super) fn verify(
    lane_start: &RecoverStart,
    challenge: &AuthChallenge,
    expected: super::server::Expected,
    binding: &[u8; 32],
    finish: &LoginFinish,
) -> Result<VerifiedLogin, NetworkError> {
    let transcript = recover_transcript(CID, binding, lane_start, challenge);
    expected.bind(transcript).verify(finish)
}

pub(super) async fn recover(
    record: Option<&PqAuthRecord>,
    username: &str,
    phrase: &RecoveryPhrase,
) -> Result<VerifiedLogin, NetworkError> {
    let binding = channel_binding(b"alice-transfer", b"bob-transfer");
    let run = lane(record, username, phrase);
    let (start, challenge) = (run.start.clone(), run.challenge.clone());
    let (finish, expected, binding) = run.proof(&binding).await;
    verify(&start, &challenge, expected, &binding, &finish)
}

pub(super) fn failed(result: Result<VerifiedLogin, NetworkError>) -> bool {
    matches!(result, Err(err) if err.code == ErrorCode::PqSignInFailed)
}

/// Control: build the factor's `info` from the username alone and the first inequality fails.
#[test]
fn a_phrase_factor_is_bound_to_its_server_and_its_username() {
    let seed = RecoverySeed::from_bytes([7u8; 32]);
    let here = ek(&phrase_of(&seed, DOMAIN), "alice");
    assert_eq!(here, ek(&phrase_of(&seed, DOMAIN), "alice"));
    assert_ne!(here, ek(&phrase_of(&seed, "other.example"), "alice"));
    assert_ne!(here, ek(&phrase_of(&seed, DOMAIN), "bob"));
    assert_ne!(
        here,
        ek(
            &phrase_of(&RecoverySeed::from_bytes([8u8; 32]), DOMAIN),
            "alice"
        )
    );
    for bad in ["".to_string(), "a".repeat(65536)] {
        let err = RecoveryPhrase::new(seed.clone(), bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::RecoveryDomainInvalid);
    }
}

#[test]
fn a_typed_phrase_reads_in_any_case_and_spacing_and_is_never_printed() {
    let seed = RecoverySeed::from_bytes(core::array::from_fn(|i| (i * 13) as u8));
    let words = seed.words();
    assert_eq!(words.len(), 24);
    let typed = format!("  {}\n", words.join("  ").to_uppercase());
    assert_eq!(
        RecoverySeed::parse(&typed).unwrap().as_bytes(),
        seed.as_bytes()
    );
    let mut swapped = words.clone();
    swapped.swap(0, 1);
    let err = RecoverySeed::parse(&swapped.join(" ")).unwrap_err();
    assert_eq!(err.code, ErrorCode::RecoveryPhraseUnreadable);
    assert!(!format!("{seed:?}").contains(&words[0]));
    assert!(!format!("{:?}", phrase_of(&seed, DOMAIN)).contains(&words[0]));
}

#[tokio::test]
async fn a_new_phrase_replaces_the_codes_and_the_phrase_before_it() {
    let (mut record, _) = register("pw").await;
    let first = with_phrase(&mut record).await;
    let kinds = |r: &PqAuthRecord| r.factors().iter().map(|f| f.kind).collect::<Vec<_>>();
    assert_eq!(
        kinds(&record),
        [FactorKind::Password, FactorKind::RecoveryPhrase]
    );
    let id = record.usable(FactorKind::RecoveryPhrase).next().unwrap().id;
    assert_eq!(id, 12, "a first phrase is numbered where the decoy's is");
    let second = with_phrase(&mut record).await;
    assert_ne!(first.as_bytes(), second.as_bytes());
    assert_eq!(record.usable(FactorKind::RecoveryPhrase).count(), 1);
    let refused = record.remove(13).unwrap_err();
    assert_eq!(refused.code, ErrorCode::PqSignInPolicy);
}

#[tokio::test]
async fn the_phrase_signs_in_to_a_recovery_session_again_and_again() {
    let (mut record, _) = register("pw").await;
    let seed = with_phrase(&mut record).await;
    let phrase = phrase_of(&seed, DOMAIN);
    for _ in 0..2 {
        let verified = sign_in(&record, None, Some(RecoveryOffer::Phrase(&phrase))).await;
        let verified = verified.unwrap();
        assert_eq!(verified.scope, SessionScope::Recovery);
        record.record_use(&verified.used, 9).unwrap();
    }
    let with_password = sign_in(&record, Some("pw"), Some(RecoveryOffer::Phrase(&phrase)));
    assert_eq!(with_password.await.unwrap().scope, SessionScope::Recovery);
}

#[tokio::test]
async fn an_old_a_foreign_and_a_wrong_phrase_all_fail_alike() {
    let (mut record, _) = register("pw").await;
    let old = phrase_of(&with_phrase(&mut record).await, DOMAIN);
    let current = phrase_of(&with_phrase(&mut record).await, DOMAIN);
    let foreign_server = phrase_of(current.seed(), "other.example");
    let random = phrase_of(&RecoverySeed::generate(), DOMAIN);
    for phrase in [&old, &foreign_server, &random] {
        assert!(failed(
            sign_in(&record, None, Some(RecoveryOffer::Phrase(phrase))).await
        ));
        assert!(failed(recover(Some(&record), "alice", phrase).await));
    }
    // Bob's phrase, offered for Alice: his factor's key is not hers, so it is a decoy.
    let (mut bob, _) = register("pw").await;
    let bobs = phrase_of(&with_phrase(&mut bob).await, DOMAIN);
    assert!(failed(recover(Some(&record), "alice", &bobs).await));
    assert!(recover(Some(&record), "alice", &current).await.is_ok());
}

#[tokio::test]
async fn the_recovery_lane_admits_to_a_recovery_scope_only() {
    let (mut record, _) = register("pw").await;
    let phrase = phrase_of(&with_phrase(&mut record).await, DOMAIN);
    let verified = recover(Some(&record), "alice", &phrase).await.unwrap();
    assert_eq!(verified.scope, SessionScope::Recovery);
    let factor = record.usable(FactorKind::RecoveryPhrase).next().unwrap().id;
    assert_eq!(verified.used, [factor]);
}
