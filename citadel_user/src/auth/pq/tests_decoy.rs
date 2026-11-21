//! An unknown username must be indistinguishable from a real password account: the same shape,
//! the same sizes, values as stable across logins as a real account's, and fresh ciphertexts.

use super::messages::{transcript_bytes, ChallengeBody, FactorChallenges, LoginChallenge};
use super::phrase::RecoverySeed;
use super::tests::{begin, complete, is_generic_failure, register};
use super::tests_recovery::{phrase_of, with_phrase, DOMAIN};
use citadel_io::tokio;

fn factors(challenge: &LoginChallenge) -> &FactorChallenges {
    match &challenge.body {
        ChallengeBody::Factors(f) => f,
        ChallengeBody::Legacy { .. } => panic!("a decoy must never look legacy"),
    }
}

/// Everything an observer can compare without knowing any secret.
fn shape(challenge: &LoginChallenge) -> impl PartialEq + std::fmt::Debug {
    let f = factors(challenge);
    let challenges: Vec<_> = f
        .challenges
        .iter()
        .map(|c| {
            (
                c.factor_id,
                c.kind,
                c.credential_id.clone(),
                c.ct.as_bytes().len(),
            )
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
    let record = register("correct horse").await;
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
async fn an_unknown_recovery_phrase_looks_like_a_real_one() {
    let mut record = register("pw").await;
    let phrase = phrase_of(&with_phrase(&mut record).await, DOMAIN);
    let stranger = phrase_of(&RecoverySeed::generate(), DOMAIN);
    let real = begin(Some(&record), "alice", None, Some(&phrase));
    let wrong_phrase = begin(Some(&record), "alice", None, Some(&stranger));
    let unknown_user = begin(None, "alicf", None, Some(&stranger));
    assert_eq!(shape(&real.challenge), shape(&wrong_phrase.challenge));
    assert_eq!(
        shape(&wrong_phrase.challenge),
        shape(&unknown_user.challenge)
    );
    assert!(is_generic_failure(&complete(wrong_phrase).await));
    assert!(is_generic_failure(&complete(unknown_user).await));
}
