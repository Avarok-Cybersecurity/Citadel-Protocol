use super::*;
use crate::proto::link::test_policy::policy;
use crate::proto::link::{ManagedLinks, Millis, RuntimeClock};
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::prelude::ConstructorOpts;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::crypto::SecurityLevel;
use std::sync::Arc;

type Constructor = <StackedRatchet as Ratchet>::Constructor;

const CID: u64 = 77;

/// One C2S session's keys: the client's end, which seals, and the server's, which opens.
fn session_keys() -> (StackedRatchet, StackedRatchet) {
    let opts = ConstructorOpts::new_vec_init(
        crate::proto::misc::session_security_settings::DEFAULT_SESSION_CRYPTO_PARAMS,
        SecurityLevel::Standard,
    );
    let psks: &[&[u8]] = &[b"session"];
    let mut client = Constructor::new_alice(opts.clone(), CID, 0).unwrap();
    let mut server = Constructor::new_bob(CID, opts, client.stage0_alice().unwrap(), psks).unwrap();
    client
        .stage1_alice(server.stage0_bob().unwrap(), psks)
        .unwrap();
    (client.finish().unwrap(), server.finish().unwrap())
}

fn holds() -> ReattachHolds {
    ReattachHolds::new(&ManagedLinks::new(Arc::new(RuntimeClock::new()), policy()).unwrap())
}

fn binding(attempt: u64) -> ReattachBinding {
    ReattachBinding {
        connection_id: Ticket(9),
        incarnation: 3,
        attempt,
    }
}

fn frame(token: ResumeToken, r: &StackedRatchet, attempt: u64) -> Reattach {
    let binding = binding(attempt);
    Reattach {
        binding,
        resume_token: token,
        proof: seal_proof(r, &binding).unwrap(),
    }
}

/// A server holding `token`'s session, dropped at t = 1000 ms.
fn held(token: ResumeToken) -> ReattachHolds {
    let mut h = holds();
    h.hold(Ticket(9), CID, token, 3, Millis(1_000));
    h
}

#[test]
fn a_proof_opens_only_under_its_own_ratchet_and_binding() {
    let (client, server) = session_keys();
    let (_, other) = session_keys();
    let proof = seal_proof(&client, &binding(1)).unwrap();
    assert!(proof_opens(&server, &binding(1), &proof));
    assert!(
        !proof_opens(&other, &binding(1), &proof),
        "another session's keys"
    );
    assert!(
        !proof_opens(&server, &binding(2), &proof),
        "another attempt"
    );
    let mut tampered = proof.clone();
    tampered[0] ^= 1;
    assert!(!proof_opens(&server, &binding(1), &tampered));
}

#[test]
fn a_held_session_is_reattached_by_its_own_client() {
    let (token, (r, server)) = (ResumeToken::generate(), session_keys());
    let mut h = held(token);
    let f = frame(token, &r, 1);
    assert_eq!(
        h.admit(&f, Millis(2_000), |_| proof_opens(
            &server, &f.binding, &f.proof
        )),
        Ok(CID)
    );
}

#[test]
fn a_frame_admitted_once_is_never_admitted_again() {
    let (token, (r, _)) = (ResumeToken::generate(), session_keys());
    let mut h = held(token);
    let f = frame(token, &r, 5);
    assert!(h.admit(&f, Millis(2_000), |_| true).is_ok());
    h.hold(Ticket(9), CID, token, 3, Millis(3_000));
    assert_eq!(
        h.admit(&f, Millis(3_500), |_| true),
        Err(ReattachRefusal::StaleAttempt)
    );
    assert!(h
        .admit(&frame(token, &r, 6), Millis(3_500), |_| true)
        .is_ok());
}

#[test]
fn an_attached_session_is_not_held() {
    let (token, (r, _)) = (ResumeToken::generate(), session_keys());
    let mut h = held(token);
    assert!(h
        .admit(&frame(token, &r, 1), Millis(2_000), |_| true)
        .is_ok());
    let again = frame(token, &r, 2);
    assert_eq!(
        h.admit(&again, Millis(2_100), |_| true),
        Err(ReattachRefusal::NotHeld)
    );
}

#[test]
fn the_wrong_token_or_incarnation_is_not_held_and_is_never_proof_checked() {
    let (token, (r, _)) = (ResumeToken::generate(), session_keys());
    let mut h = held(token);
    let mut asked = false;
    let stranger = frame(ResumeToken::generate(), &r, 1);
    assert_eq!(
        h.admit(&stranger, Millis(2_000), |_| {
            asked = true;
            true
        }),
        Err(ReattachRefusal::NotHeld)
    );
    let mut reborn = frame(token, &r, 1);
    reborn.binding.incarnation = 4;
    assert_eq!(
        h.admit(&reborn, Millis(2_000), |_| {
            asked = true;
            true
        }),
        Err(ReattachRefusal::NotHeld)
    );
    assert!(!asked);
}

#[test]
fn a_hold_ends_at_the_grace() {
    let (token, (r, _)) = (ResumeToken::generate(), session_keys());
    let end = Millis(1_000).after(policy().reattach_grace);
    let mut h = held(token);
    assert!(h
        .admit(&frame(token, &r, 1), Millis(end.0 - 1), |_| true)
        .is_ok());
    let mut h = held(token);
    assert_eq!(
        h.admit(&frame(token, &r, 1), end, |_| true),
        Err(ReattachRefusal::GraceExpired)
    );
    let mut h = held(token);
    assert_eq!(h.expire(Millis(end.0 - 1)), Vec::<u64>::new());
    assert_eq!(h.expire(end), vec![CID]);
    h.hold(Ticket(9), CID, token, 3, end);
    h.release(Ticket(9));
    assert_eq!(
        h.admit(&frame(token, &r, 1), end, |_| true),
        Err(ReattachRefusal::NotHeld)
    );
}

#[test]
fn a_proof_that_does_not_open_is_refused_and_burns_no_attempt() {
    let (token, (r, server)) = (ResumeToken::generate(), session_keys());
    let mut h = held(token);
    let forged = frame(token, &session_keys().0, 1);
    assert_eq!(
        h.admit(&forged, Millis(2_000), |_| proof_opens(
            &server,
            &forged.binding,
            &forged.proof
        )),
        Err(ReattachRefusal::ProofInvalid)
    );
    let real = frame(token, &r, 1);
    assert!(h
        .admit(&real, Millis(2_000), |_| proof_opens(
            &server,
            &real.binding,
            &real.proof
        ))
        .is_ok());
}

#[test]
fn the_frames_cross_the_wire_intact() {
    use citadel_user::serialization::SyncIO;
    let (token, (r, server)) = (ResumeToken::generate(), session_keys());
    let sent = frame(token, &r, 1);
    let got = Reattach::deserialize_from_vector(&sent.serialize_to_vector().unwrap()).unwrap();
    assert_eq!(got.binding, sent.binding);
    assert!(got.resume_token.same_as(&token));
    assert!(proof_opens(&server, &got.binding, &got.proof));
    let ok = Reattached { latest_version: 4 };
    assert_eq!(
        Reattached::deserialize_from_vector(&ok.serialize_to_vector().unwrap()).unwrap(),
        ok
    );
    for reason in [
        ReattachRefusal::NotHeld,
        ReattachRefusal::GraceExpired,
        ReattachRefusal::StaleAttempt,
        ReattachRefusal::ProofInvalid,
    ] {
        let refused = ReattachRefused { reason };
        let back =
            ReattachRefused::deserialize_from_vector(&refused.serialize_to_vector().unwrap());
        assert_eq!(back.unwrap(), refused);
    }
}
