//! Interop through the version gate: who runs the exchange, and that the widened STAGE0 and
//! STAGE2 still read in both directions.

use super::runs_with;
use crate::constants::{PQ_SIGN_IN_SINCE, PROTOCOL_VERSION};
use crate::proto::packet_crafter::do_connect::DoConnectStage0Packet;
use crate::proto::packet_crafter::do_register::DoRegisterStage2Packet;
use crate::proto::session_resume::ResumeToken;
use citadel_user::auth::pq::kem::{FactorKeypair, FactorSeed, SEED_LEN};
use citadel_user::auth::pq::messages::{FactorTag, LoginFinish, LoginProof, RegFinish};
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use citadel_user::serialization::SyncIO;
use embedded_semver::Semver;
use serde::{Deserialize, Serialize};

fn version(major: usize, minor: usize, patch: usize) -> u32 {
    Semver::new(major, minor, patch).to_u32().unwrap()
}

#[test]
fn only_nodes_at_or_above_the_gate_run_post_quantum_sign_in() {
    let (major, minor, patch) = PQ_SIGN_IN_SINCE;
    assert!(runs_with(*PROTOCOL_VERSION), "this node must run it");
    assert!(runs_with(version(major as _, minor as _, patch as _)));
    assert!(
        !runs_with(version(0, 11, 2)),
        "0.11.2 keeps the legacy login"
    );
    assert!(!runs_with(version(0, 10, 9)));
    assert!(
        !runs_with(u32::MAX),
        "an unparseable version is not trusted"
    );
}

/// The 0.11.2 shape of STAGE0, as an older client sends it and an older server reads it.
#[derive(Serialize, Deserialize)]
struct Stage0Of0112 {
    proposed_credentials: ProposedCredentials,
    uses_filesystem: bool,
    resume_token: Option<ResumeToken>,
}

#[derive(Serialize, Deserialize)]
struct Stage2Of0112 {
    credentials: ProposedCredentials,
}

fn proof() -> LoginProof {
    LoginProof::Factors(LoginFinish {
        tags: vec![FactorTag {
            factor_id: 1,
            tag: [7u8; 32],
        }],
    })
}

#[test]
fn an_older_clients_stage0_reads_as_a_legacy_login() {
    let old = Stage0Of0112 {
        proposed_credentials: ProposedCredentials::transient("alice"),
        uses_filesystem: true,
        resume_token: Some(ResumeToken::generate()),
    };
    let read = DoConnectStage0Packet::deserialize_from_vector(&old.serialize_to_vector().unwrap())
        .unwrap();
    assert!(read.pq_proof.is_none());
    assert!(read.resume_token.is_some());
}

#[test]
fn a_new_stage0_still_reads_on_an_older_server_and_keeps_its_proof_here() {
    let new = DoConnectStage0Packet {
        proposed_credentials: ProposedCredentials::transient("alice"),
        uses_filesystem: false,
        resume_token: None,
        pq_proof: Some(proof()),
    };
    let bytes = new.serialize_to_vector().unwrap();
    let old = Stage0Of0112::deserialize_from_vector(&bytes).unwrap();
    assert!(old.resume_token.is_none());
    let here = DoConnectStage0Packet::deserialize_from_vector(&bytes).unwrap();
    assert_eq!(here.pq_proof, Some(proof()));
}

#[test]
fn stage2_reads_in_both_directions() {
    let ek = FactorKeypair::derive(&FactorSeed::new([1u8; SEED_LEN]))
        .unwrap()
        .encapsulation_key()
        .clone();
    let finish = RegFinish {
        password_ek: ek,
        recovery_eks: Vec::new(),
    };
    let new = DoRegisterStage2Packet {
        credentials: ProposedCredentials::transient("alice"),
        pq: Some(finish.clone()),
    };
    let bytes = new.serialize_to_vector().unwrap();
    assert!(Stage2Of0112::deserialize_from_vector(&bytes).is_ok());
    let here = DoRegisterStage2Packet::deserialize_from_vector(&bytes).unwrap();
    assert_eq!(here.pq, Some(finish));

    let old = Stage2Of0112 {
        credentials: ProposedCredentials::transient("alice"),
    };
    let read = DoRegisterStage2Packet::deserialize_from_vector(&old.serialize_to_vector().unwrap())
        .unwrap();
    assert!(read.pq.is_none());
}

/// A client below 0.12 sends no `AUTH_START` and so cannot carry an admission token: a refusal
/// tells it to update, not to complete a check it has no way to show.
#[test]
fn a_client_below_the_gate_is_told_to_update_and_one_at_it_is_not() {
    use super::admission::is_legacy_client;
    let (major, minor, patch) = PQ_SIGN_IN_SINCE;
    let gate = version(major.into(), minor.into(), patch.into());
    assert!(!is_legacy_client(gate));
    assert!(is_legacy_client(version(0, 11, 2)));
    let refusal = citadel_user::auth::pq::admission::refusal_error(
        citadel_user::auth::pq::admission::AdmissionRefusal::Required,
        is_legacy_client(version(0, 11, 2)),
    );
    assert_eq!(
        refusal.code,
        citadel_io::ErrorCode::PqSignInAdmissionNeedsUpdate
    );
    assert!(refusal.into_string().contains("update your app"));
}
