//! The admission check runs before any OPRF evaluation.
//!
//! A blinded element that is not a valid ristretto255 point makes the OPRF evaluation fail. So
//! for a login carrying one, the error says which ran first: a refusal from the policy means
//! the OPRF never ran; an OPRF error means it ran first. Proto's `AUTH_START` and `PQ_START`
//! handlers build their challenge inside `admission::then`, which these call the same way.

use super::admission::{
    self, AdmissionContext, AdmissionKind, AdmissionPolicy, AdmissionRefusal, AdmissionToken,
};
use super::messages::{LoginStart, RegStart};
use super::record::PqAuthRecord;
use super::server::{build_login_challenge, registration_reply, AccountAuth};
use super::tests::{register, settings};
use async_trait::async_trait;
use citadel_io::{tokio, ErrorCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Wants `good`; counts its calls.
#[derive(Default)]
struct Wants {
    calls: AtomicUsize,
}

#[async_trait]
impl AdmissionPolicy for Wants {
    async fn admit(&self, ctx: AdmissionContext) -> Result<(), AdmissionRefusal> {
        let _ = self.calls.fetch_add(1, Ordering::SeqCst);
        match ctx.token.as_ref().map(AdmissionToken::as_str) {
            None => Err(AdmissionRefusal::Required),
            Some("good") => Ok(()),
            Some(_) => Err(AdmissionRefusal::Failed("invalid-input-response".into())),
        }
    }
}

const NOT_A_POINT: [u8; 32] = [0xff; 32];

fn ctx(kind: AdmissionKind, token: Option<&str>) -> AdmissionContext {
    AdmissionContext {
        username: "alice".into(),
        kind,
        token: token.map(AdmissionToken::new),
        remote_addr: None,
    }
}

fn bad_login() -> LoginStart {
    LoginStart {
        username: "alice".into(),
        client_nonce: [1; 32],
        oprf_blinded: Some(NOT_A_POINT.to_vec()),
        recovery: None,
        admission: None,
        resume: None,
    }
}

/// The error, and whether the OPRF was reached at all.
async fn challenge(
    policy: &Arc<dyn AdmissionPolicy>,
    record: &PqAuthRecord,
    token: Option<&str>,
) -> (Option<ErrorCode>, bool) {
    let reached = AtomicUsize::new(0);
    let ctx = Some(ctx(AdmissionKind::SignIn, token));
    let built = admission::then(Some(policy), ctx, false, || {
        let _ = reached.fetch_add(1, Ordering::SeqCst);
        build_login_challenge(&settings(), AccountAuth::PostQuantum(record), &bad_login())
    })
    .await;
    (
        built.err().map(|err| err.code),
        reached.load(Ordering::SeqCst) > 0,
    )
}

#[tokio::test]
async fn a_sign_in_is_refused_before_the_oprf_runs() {
    let (record, _) = register("pw").await;
    let wants = Arc::new(Wants::default());
    let policy: Arc<dyn AdmissionPolicy> = wants.clone();
    let (missing, reached) = challenge(&policy, &record, None).await;
    assert_eq!(missing, Some(ErrorCode::PqSignInAdmissionRequired));
    assert!(!reached, "the OPRF ran for a login without a token");
    let (bad, reached) = challenge(&policy, &record, Some("forged")).await;
    assert_eq!(bad, Some(ErrorCode::PqSignInAdmissionFailed));
    assert!(!reached, "the OPRF ran for a login with a refused token");
    // The control: admitted, the same login reaches the OPRF, which refuses the input.
    let (admitted, reached) = challenge(&policy, &record, Some("good")).await;
    assert!(reached, "an admitted login never reached the OPRF");
    assert!(
        !matches!(
            admitted,
            None | Some(ErrorCode::PqSignInAdmissionRequired | ErrorCode::PqSignInAdmissionFailed)
        ),
        "the garbage input did not reach the OPRF: {admitted:?}"
    );
    let asked = wants.calls.load(Ordering::SeqCst);
    assert_eq!(asked, 3, "asked once per login");
}

#[tokio::test]
async fn a_registration_is_refused_before_the_oprf_runs() {
    let policy: Arc<dyn AdmissionPolicy> = Arc::new(Wants::default());
    let start = RegStart {
        username: "bob".into(),
        oprf_blinded: NOT_A_POINT.to_vec(),
        admission: None,
    };
    let register = |token: Option<&str>| {
        let ctx = ctx(AdmissionKind::Register, token);
        let start = start.clone();
        let policy = policy.clone();
        async move {
            admission::then(Some(&policy), Some(ctx), false, || {
                registration_reply(&settings(), &start)
            })
            .await
            .err()
            .map(|err| err.code)
        }
    };
    assert_eq!(
        register(None).await,
        Some(ErrorCode::PqSignInAdmissionRequired)
    );
    let admitted = register(Some("good")).await;
    assert!(
        !matches!(admitted, None | Some(ErrorCode::PqSignInAdmissionRequired)),
        "the garbage input did not reach the OPRF: {admitted:?}"
    );
}

#[tokio::test]
async fn without_a_policy_everyone_is_admitted_and_a_login_not_asked_is_not() {
    let (record, _) = register("pw").await;
    let ran = admission::then(None, Some(ctx(AdmissionKind::SignIn, None)), false, || {
        Ok(7)
    })
    .await;
    assert_eq!(ran.unwrap(), 7);
    let wants = Arc::new(Wants::default());
    let policy: Arc<dyn AdmissionPolicy> = wants.clone();
    let _ = admission::then(Some(&policy), None, false, || {
        build_login_challenge(&settings(), AccountAuth::PostQuantum(&record), &bad_login())
    })
    .await;
    assert_eq!(
        wants.calls.load(Ordering::SeqCst),
        0,
        "a login not asked was asked"
    );
}
