//! Shared steps for the recovery suites: an account with a phrase, a recovery from a device, a
//! phrase sign-in, and the one failure every refused attempt reads as.

use crate::common::pq::{login, PASSWORD};
use citadel_io::ErrorCode;
use citadel_sdk::prelude::*;
use std::net::SocketAddr;

pub const DOMAIN: &str = "localhost";
pub const NEW_PASSWORD: &str = "a brand new passphrase";

pub fn password() -> SignInFactors {
    SignInFactors::password(PASSWORD)
}

/// Registers `user` and replaces its codes with a phrase; returns the phrase.
pub async fn with_phrase(
    remote: &NodeRemote<StackedRatchet>,
    addr: SocketAddr,
    user: &str,
) -> Result<RecoveryPhrase, NetworkError> {
    let _ = remote
        .register_with_defaults(addr, user, user, PASSWORD)
        .await?;
    let conn = login(remote, user, PASSWORD).await?;
    let words = regenerate(&conn, password()).await?;
    conn.disconnect().await?;
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
        .recover(addr, asking(user, phrase), Default::default(), None)
        .await
}

pub async fn phrase_session(
    device: &NodeRemote<StackedRatchet>,
    user: &str,
    phrase: &RecoveryPhrase,
) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
    let factors = SignInFactors::recovery_phrase(phrase.clone());
    device
        .connect_with_defaults(AuthenticationRequest::sign_in(user.to_string(), factors))
        .await
}

/// Every refusal reads the same over the wire: a wrong proof's message, nothing more.
pub fn assert_failed(result: Result<RecoverSuccess, NetworkError>, what: &str) {
    let err = result.expect_err(what).into_string();
    assert_eq!(err, ErrorCode::PqSignInFailed.raw_string(), "{what}");
}
