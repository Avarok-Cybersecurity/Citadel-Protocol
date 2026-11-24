//! A refusal's public challenge: it rides beside the `PqSignInAdmissionRequired` error, only on
//! that error, and a `RegStart` says whether its client reads one.

use super::admission::{
    self, challenge_of, refusal_error, refusal_from_message, AdmissionChallenge, AdmissionContext,
    AdmissionKind, AdmissionPolicy, AdmissionRefusal,
};
use super::messages::{LoginStart, RegStart};
use super::server::{build_login_challenge, AccountAuth};
use super::tests::{register, settings};
use crate::serialization::SyncIO;
use async_trait::async_trait;
use citadel_io::{tokio, ErrorCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn challenge() -> AdmissionChallenge {
    AdmissionChallenge::turnstile("0x4AAA-site-key", Some("acme".into()))
}

#[test]
fn a_required_refusal_carries_its_challenge_and_its_plain_message() {
    let with = refusal_error(AdmissionRefusal::Required(Some(challenge())));
    let without = refusal_error(AdmissionRefusal::Required(None));
    assert_eq!(with.code, ErrorCode::PqSignInAdmissionRequired);
    assert_eq!(challenge_of(&with), Some(&challenge()));
    assert_eq!(challenge_of(&without), None, "an absent challenge appeared");
    assert_eq!(with.to_string(), without.to_string(), "the message changed");
}

#[test]
fn a_failure_keeps_the_challenge_only_on_the_refusal_that_asks_for_one() {
    let required = ErrorCode::PqSignInAdmissionRequired.raw_string();
    let kept = refusal_from_message(required, Some(challenge())).unwrap();
    assert_eq!(challenge_of(&kept), Some(&challenge()));
    let absent = refusal_from_message(required, None).unwrap();
    assert_eq!(challenge_of(&absent), None);

    let failed = refusal_error(AdmissionRefusal::Failed("expired".into())).into_string();
    let dropped = refusal_from_message(&failed, Some(challenge())).unwrap();
    assert_eq!(dropped.code, ErrorCode::PqSignInAdmissionFailed);
    assert_eq!(challenge_of(&dropped), None);
    assert!(refusal_from_message("Authentication failed", Some(challenge())).is_none());
}

#[test]
fn reg_start_round_trips() {
    let start = RegStart {
        username: "bob".into(),
        oprf_blinded: vec![1, 2],
        admission: None,
    };
    let bytes = start.serialize_to_vector().unwrap();
    assert_eq!(RegStart::deserialize_from_vector(&bytes).unwrap(), start);
}

struct Challenges(AtomicBool);

#[async_trait]
impl AdmissionPolicy for Challenges {
    async fn admit(&self, _: AdmissionContext) -> Result<(), AdmissionRefusal> {
        self.0.store(true, Ordering::SeqCst);
        Err(AdmissionRefusal::Required(Some(challenge())))
    }

    fn resume_grace(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
}

#[tokio::test]
async fn a_challenging_policy_is_still_asked_before_the_oprf() {
    let record = register("pw").await;
    let asked = Arc::new(Challenges(AtomicBool::new(false)));
    let policy: Arc<dyn AdmissionPolicy> = asked.clone();
    let reached = AtomicBool::new(false);
    let start = LoginStart {
        username: "alice".into(),
        client_nonce: [1; 32],
        oprf_blinded: Some([0xff; 32].to_vec()),
        recovery: None,
        admission: None,
        resume: None,
        resume_credential: None,
    };
    let ctx = AdmissionContext {
        username: "alice".into(),
        kind: AdmissionKind::SignIn,
        token: None,
        remote_addr: None,
    };
    let built = admission::then(Some(&policy), Some(ctx), || {
        reached.store(true, Ordering::SeqCst);
        build_login_challenge(&settings(), AccountAuth::PostQuantum(&record), &start)
    })
    .await;
    let err = built.err().expect("a refused login was admitted");
    assert!(asked.0.load(Ordering::SeqCst), "the policy was not asked");
    assert!(
        !reached.load(Ordering::SeqCst),
        "the OPRF ran before the refusal"
    );
    assert_eq!(challenge_of(&err), Some(&challenge()));
}
