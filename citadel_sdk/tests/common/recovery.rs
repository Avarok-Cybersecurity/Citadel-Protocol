//! Shared steps for the recovery suites: an account with a phrase, a recovery from a device, a
//! phrase sign-in, and the one failure every refused attempt reads as.

use crate::common::pq::PASSWORD;
use citadel_io::ErrorCode;
use citadel_sdk::prelude::*;
use std::net::SocketAddr;

pub const DOMAIN: &str = "localhost";
pub const NEW_PASSWORD: &str = "a brand new passphrase";

pub fn password() -> SignInFactors {
    SignInFactors::password(PASSWORD)
}

/// Registers `user`, which is given a recovery phrase in place of codes; returns the phrase.
pub async fn with_phrase(
    remote: &NodeRemote<StackedRatchet>,
    addr: SocketAddr,
    user: &str,
) -> Result<RecoveryPhrase, NetworkError> {
    let domain = Some(DOMAIN.to_string());
    let reg = remote.register_admitted(
        addr,
        user,
        user,
        PASSWORD,
        citadel_sdk::prelude::default_session_security_settings(),
        None,
        None,
        domain,
        CertVerification::SelfSignedAccepted,
    );
    let reg = reg.await?;
    let words = reg
        .recovery_phrase
        .expect("a new account was given no phrase");
    Ok(phrase(&words))
}

pub async fn regenerate(
    conn: &CitadelClientServerConnection<StackedRatchet>,
    step_up: SignInFactors,
) -> Result<Vec<String>, NetworkError> {
    let op = SignInManagementOp::RegenerateRecoveryPhrase {
        canonical_domain: DOMAIN.into(),
    };
    match conn.manage_sign_in(op, step_up).await? {
        SignInManagementOutcome::RecoveryPhrase(words) => Ok(words),
        other => panic!("not a phrase: {other:?}"),
    }
}

pub fn phrase(words: &[String]) -> RecoveryPhrase {
    let seed = RecoverySeed::parse(&words.join(" ")).unwrap();
    RecoveryPhrase::new(seed, DOMAIN).unwrap()
}

pub fn asking(user: &str, phrase: &RecoveryPhrase) -> AccountRecovery {
    AccountRecovery {
        username: user.to_string(),
        phrase: phrase.clone(),
        device_label: "Laptop".into(),
        admission: None,
    }
}

pub async fn recover(
    device: &NodeRemote<StackedRatchet>,
    addr: SocketAddr,
    user: &str,
    phrase: &RecoveryPhrase,
) -> Result<RecoverSuccess, NetworkError> {
    device
        .recover(
            addr,
            asking(user, phrase),
            citadel_sdk::prelude::default_session_security_settings(),
            None,
            CertVerification::SelfSignedAccepted,
        )
        .await
}

pub async fn phrase_session(
    device: &NodeRemote<StackedRatchet>,
    user: &str,
    phrase: &RecoveryPhrase,
) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
    let factors = SignInFactors::recovery_phrase(phrase.clone());
    device
        .connect_with_defaults(
            AuthenticationRequest::sign_in(user.to_string(), factors),
            CertVerification::SelfSignedAccepted,
        )
        .await
}

/// Every refusal reads the same: a wrong proof's code and message, nothing more.
pub fn assert_failed(result: Result<RecoverSuccess, NetworkError>, what: &str) {
    let err = result.expect_err(what);
    assert_eq!(err.code(), ErrorCode::PqSignInFailed, "{what}: {err}");
    assert_eq!(
        err.into_string(),
        ErrorCode::PqSignInFailed.raw_string(),
        "{what}"
    );
}
