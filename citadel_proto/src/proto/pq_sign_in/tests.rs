//! Post-quantum sign-in on the wire, through the version gate: a node below it is refused by name
//! before any sign-in message is read, and STAGE0 and STAGE2 read only in their current shape.

use crate::constants::{PQ_SIGN_IN_SINCE, PROTOCOL_VERSION};
use crate::proto::packet_crafter::do_connect::DoConnectStage0Packet;
use crate::proto::packet_crafter::do_register::DoRegisterStage2Packet;
use crate::proto::session_resume::ResumeToken;
use crate::proto::version_gate::check_peer_protocol_version;
use citadel_io::ErrorCode;
use citadel_user::auth::pq::kem::{FactorKeypair, FactorSeed, SEED_LEN};
use citadel_user::auth::pq::messages::{FactorTag, LoginFinish, LoginProof, RegFinish};
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use citadel_user::serialization::SyncIO;
use embedded_semver::Semver;
use serde::{Deserialize, Serialize};

fn version(major: usize, minor: usize, patch: usize) -> u32 {
    Semver::new(major, minor, patch).to_u32().unwrap()
}

/// A node that predates post-quantum sign-in (and so would log in or register the legacy way) is
/// refused at the handshake; this node is admitted.
#[test]
fn a_node_below_post_quantum_sign_in_is_refused_by_name() {
    let (major, minor, _) = PQ_SIGN_IN_SINCE;
    assert!(minor > 0, "the gate names a release with a predecessor");
    for older in [
        version(major.into(), (minor - 1).into(), 2),
        version(0, 10, 9),
    ] {
        let refused = check_peer_protocol_version(older).unwrap_err();
        assert_eq!(refused.code, ErrorCode::ProtocolVersionUnsupported);
    }
    assert!(check_peer_protocol_version(*PROTOCOL_VERSION).is_ok());
}

/// The 0.11.2 shape of STAGE0, as a client below post-quantum sign-in sent it.
#[derive(Serialize, Deserialize)]
struct Stage0Of0112 {
    proposed_credentials: ProposedCredentials,
    uses_filesystem: bool,
    resume_token: Option<ResumeToken>,
}

/// The 0.11.2 shape of STAGE2.
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

/// Control: read `DoConnectStage0Packet::pq_proof` with `ok_or_default` and the older shape reads.
#[test]
fn an_older_clients_stage0_does_not_read_and_a_current_one_does() {
    let old = Stage0Of0112 {
        proposed_credentials: ProposedCredentials::transient("alice"),
        uses_filesystem: true,
        resume_token: Some(ResumeToken::generate()),
    };
    let refused =
        DoConnectStage0Packet::deserialize_from_vector(&old.serialize_to_vector().unwrap())
            .err()
            .expect("an older STAGE0 read");
    assert_eq!(refused.code, ErrorCode::DeserializationFailed);

    let new = DoConnectStage0Packet {
        proposed_credentials: ProposedCredentials::transient("alice"),
        uses_filesystem: false,
        resume_token: None,
        pq_proof: Some(proof()),
    };
    let bytes = new.serialize_to_vector().unwrap();
    let here = DoConnectStage0Packet::deserialize_from_vector(&bytes).unwrap();
    assert_eq!(here.pq_proof, Some(proof()));
}

#[test]
fn a_current_stage2_reads() {
    let ek = FactorKeypair::derive(&FactorSeed::new([1u8; SEED_LEN]))
        .unwrap()
        .encapsulation_key()
        .clone();
    let finish = RegFinish {
        password_ek: ek.clone(),
        recovery_phrase_ek: None,
    };
    let with_phrase = DoRegisterStage2Packet {
        credentials: ProposedCredentials::transient("alice"),
        pq: Some(RegFinish {
            recovery_phrase_ek: Some(ek),
            ..finish.clone()
        }),
    };
    let bytes = with_phrase.serialize_to_vector().unwrap();
    let read = DoRegisterStage2Packet::deserialize_from_vector(&bytes).unwrap();
    assert_eq!(read.pq, with_phrase.pq);
    let new = DoRegisterStage2Packet {
        credentials: ProposedCredentials::transient("alice"),
        pq: Some(finish.clone()),
    };
    let bytes = new.serialize_to_vector().unwrap();
    let here = DoRegisterStage2Packet::deserialize_from_vector(&bytes).unwrap();
    assert_eq!(here.pq, Some(finish));
}

/// A STAGE2 with no `pq` field is an older client's, and does not read as a legacy registration.
/// Control: read `DoRegisterStage2Packet::pq` with `ok_or_default` again and it reads as `None`.
#[test]
fn an_older_clients_stage2_is_refused() {
    let old = Stage2Of0112 {
        credentials: ProposedCredentials::transient("alice"),
    };
    let refused =
        DoRegisterStage2Packet::deserialize_from_vector(&old.serialize_to_vector().unwrap())
            .err()
            .expect("an older STAGE2 read");
    assert_eq!(refused.code, ErrorCode::DeserializationFailed);
}

/// The legacy registration mode still sends a STAGE2, with no factors, and it reads.
#[test]
fn a_legacy_mode_stage2_reads() {
    let legacy = DoRegisterStage2Packet {
        credentials: ProposedCredentials::transient("alice"),
        pq: None,
    };
    let bytes = legacy.serialize_to_vector().unwrap();
    let read = DoRegisterStage2Packet::deserialize_from_vector(&bytes).unwrap();
    assert!(read.pq.is_none());
}
