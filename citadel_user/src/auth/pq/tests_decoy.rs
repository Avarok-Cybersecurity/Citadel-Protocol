//! An unknown username must be indistinguishable from a real password account: the same shape,
//! the same sizes, values as stable across logins as a real account's, and fresh ciphertexts.

use super::messages::{transcript_bytes, ChallengeBody, FactorChallenges, LoginChallenge};
use super::recovery::RecoveryCode;
use super::tests::{begin, complete, is_generic_failure, register};
use citadel_io::tokio;
use citadel_types::auth::FactorKind;

fn factors(challenge: &LoginChallenge) -> &FactorChallenges {
    let ChallengeBody::Factors(f) = &challenge.body;
    f
}

/// Everything an observer can compare without knowing any secret. A recovery code's id is left
/// out: it is the code's position, which a decoy draws from the same range.
fn shape(challenge: &LoginChallenge) -> impl PartialEq + std::fmt::Debug {
    let f = factors(challenge);
    let challenges: Vec<_> = f
        .challenges
        .iter()
        .map(|c| {
            let id = (c.kind != FactorKind::RecoveryCode).then_some(c.factor_id);
            (id, c.kind, c.credential_id.clone(), c.ct.as_bytes().len())
        })
        .collect();
    (
        transcript_bytes(challenge).len(),
        f.oprf_evaluated.as_ref().map(Vec::len),
        f.ksf,
        challenges,
    )
}

#[citadel_io::tokio::test]
async fn an_unknown_username_looks_like_a_password_account() {
    let (record, _) = register("correct horse").await;
    let real = begin(Some(&record), "alice", Some("guess"), None);
    let unknown = begin(None, "alicf", Some("guess"), None);
    assert_eq!(shape(&real.challenge), shape(&unknown.challenge));

    // A real account's salts are the same at every login; so are a decoy's.
    let unknown_again = begin(None, "alicf", Some("guess"), None);
    let (a, b) = (
        factors(&unknown.challenge),
        factors(&unknown_again.challenge),
    );
    assert_eq!(
        (a.salt_user, a.prf_eval_salt),
        (b.salt_user, b.prf_eval_salt)
    );
    // A real account's ciphertexts are fresh at every login; so are a decoy's.
    assert_ne!(a.challenges[0].ct, b.challenges[0].ct);
    assert_ne!(
        a.salt_user,
        factors(&begin(None, "carol", None, None).challenge).salt_user
    );

    // The OPRF answers an unknown name the same way it answers a real one: the same input under
    // the same name always gives the same output, whether or not the account exists.
    assert!(is_generic_failure(&complete(unknown_again).await));
    assert!(is_generic_failure(&complete(real).await));
}

#[citadel_io::tokio::test]
async fn an_unknown_recovery_code_looks_like_a_real_one() {
    let (record, codes) = register("correct horse").await;
    let stranger = RecoveryCode::generate();
    let real = begin(Some(&record), "alice", None, Some(&codes[0]));
    let wrong_code = begin(Some(&record), "alice", None, Some(&stranger));
    let unknown_user = begin(None, "alicf", None, Some(&stranger));
    assert_eq!(shape(&real.challenge), shape(&wrong_code.challenge));
    assert_eq!(shape(&wrong_code.challenge), shape(&unknown_user.challenge));
    for x in [&real, &wrong_code, &unknown_user] {
        let id = factors(&x.challenge).challenges[0].factor_id;
        assert!(
            (2..=11).contains(&id),
            "recovery code ids are 2..=11, got {id}"
        );
    }
    assert!(is_generic_failure(&complete(wrong_code).await));
    assert!(is_generic_failure(&complete(unknown_user).await));
}
