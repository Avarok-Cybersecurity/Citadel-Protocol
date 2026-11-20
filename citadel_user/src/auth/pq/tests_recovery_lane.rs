//! The recovery lane: what a proof is bound to, and what an unknown name is answered with.

use super::channel_binding;
use super::client::ClientLogin;
use super::messages::AuthChallenge;
use super::server::build_recovery_challenge;
use super::tests::{password, register, settings};
use super::tests_recovery::*;
use citadel_io::{tokio, ErrorCode};

/// Control: leave the channel binding out of `recover_transcript` and the relayed proof verifies.
#[tokio::test]
async fn a_proof_fits_one_key_exchange_one_device_and_one_challenge() {
    let (mut record, _) = register("pw").await;
    let phrase = phrase_of(&with_phrase(&mut record).await, DOMAIN);
    let binding = channel_binding(b"alice-transfer", b"bob-transfer");

    // Relayed: the prover's exchange differs from the server's.
    let run = lane(Some(&record), "alice", &phrase);
    let (start, challenge) = (run.start.clone(), run.challenge.clone());
    let (finish, expected, _) = run.proof(&binding).await;
    let relayed = channel_binding(b"mallory-transfer", b"bob-transfer");
    assert!(failed(verify(
        &start, &challenge, expected, &relayed, &finish
    )));

    // Another device's label.
    let run = lane(Some(&record), "alice", &phrase);
    let (mut start, challenge) = (run.start.clone(), run.challenge.clone());
    let (finish, expected, _) = run.proof(&binding).await;
    start.device.label = "mallory's phone".into();
    assert!(failed(verify(
        &start, &challenge, expected, &binding, &finish
    )));

    // Replayed: a captured proof against a fresh challenge.
    let first = lane(Some(&record), "alice", &phrase);
    let (finish, _, _) = first.proof(&binding).await;
    let second = lane(Some(&record), "alice", &phrase);
    let (start, challenge) = (second.start.clone(), second.challenge.clone());
    assert!(failed(verify(
        &start,
        &challenge,
        second.expected,
        &binding,
        &finish
    )));
}

#[tokio::test]
async fn an_unknown_name_gets_a_phrase_shaped_decoy_and_cannot_recover() {
    let (mut record, _) = register("pw").await;
    let phrase = phrase_of(&with_phrase(&mut record).await, DOMAIN);
    let real = lane(Some(&record), "alice", &phrase).challenge;
    let decoy = lane(None, "nobody", &phrase).challenge;
    let shape = |c: &AuthChallenge| match &c.challenge.body {
        super::messages::ChallengeBody::Factors(f) => f
            .challenges
            .iter()
            .map(|c| (c.factor_id, c.kind, c.ct.as_bytes().len()))
            .collect::<Vec<_>>(),
        _ => panic!("a recovery is never legacy"),
    };
    assert_eq!(shape(&real), shape(&decoy));
    assert!(failed(recover(None, "nobody", &phrase).await));
}

#[tokio::test]
async fn a_password_start_is_not_a_recovery_start() {
    let (record, _) = register("pw").await;
    let (login, _) = ClientLogin::start("alice", Some(&password("pw")), None).unwrap();
    let refused = build_recovery_challenge(&settings(), Some(&record), &login);
    assert_eq!(
        refused.err().map(|e| e.code),
        Some(ErrorCode::PqSignInMalformed)
    );
}
