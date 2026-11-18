//! Wire compatibility with 0.12.2 peers: the sign-in messages this node sends a peer below
//! `SECURITY_KEY_CEREMONY_SINCE` are byte for byte what a 0.12.2 node sends, what such a peer sends
//! reads here, and both sides hash the same transcripts.
//!
//! The fixtures are the encodings SDK f419b95e (protocol 0.12.2) produces, written by
//! `fixtures_0_12_2/generator.rs` run in that tree against its own types.

use super::challenge::{ceremony, read};
use super::layout_of;
use super::manage::sendable;
use crate::constants::PROTOCOL_VERSION;
use crate::proto::peer::peer_layer::PeerSignal;
use citadel_io::ErrorCode;
use citadel_types::auth::{FactorKind, SignInManagementOp};
use citadel_user::auth::pq::kem::{EncapsulationKey, KemCiphertext};
use citadel_user::auth::pq::messages::*;
use citadel_user::auth::pq::oprf::OprfSeed;
use citadel_user::auth::pq::record::KsfParams;
use citadel_user::auth::pq::server::PqAuthServerSettings;
use citadel_user::auth::pq::{login_transcript, management_transcript};
use citadel_user::serialization::SyncIO;
use embedded_semver::Semver;

const CID: u64 = 7;

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("fixtures_0_12_2/", $name)).as_slice()
    };
}

fn v0_12_2() -> u32 {
    Semver::new(0, 12, 2).to_u32().unwrap()
}

fn ct(fill: u8) -> KemCiphertext {
    KemCiphertext::try_from(vec![fill; 1568]).unwrap()
}

fn ek() -> EncapsulationKey {
    EncapsulationKey::try_from(fixture!("new_key_ek.bin").to_vec()).unwrap()
}

fn start() -> LoginStart {
    LoginStart {
        username: "alice".into(),
        client_nonce: [0x11; 32],
        oprf_blinded: Some(vec![0x22; 32]),
        recovery: None,
        admission: None,
        resume: None,
    }
}

fn factors() -> LoginChallenge {
    LoginChallenge {
        server_nonce: [0x33; 32],
        body: ChallengeBody::Factors(FactorChallenges {
            oprf_evaluated: Some(vec![0x44; 32]),
            salt_user: [0x55; 32],
            prf_eval_salt: [0x66; 32],
            ksf: KsfParams::FLOOR,
            challenges: vec![
                FactorChallenge {
                    factor_id: 1,
                    kind: FactorKind::Password,
                    credential_id: None,
                    ct: ct(0xC1),
                },
                FactorChallenge {
                    factor_id: 2,
                    kind: FactorKind::SecurityKey,
                    credential_id: Some(b"cred-1".to_vec()),
                    ct: ct(0xC2),
                },
            ],
        }),
    }
}

fn settings() -> PqAuthServerSettings {
    PqAuthServerSettings::new(OprfSeed::from_bytes([1; 32]), KsfParams::FLOOR)
        .unwrap()
        .with_security_key_rp_id("example.com")
        .unwrap()
}

/// What this node sends a 0.12.2 client: the challenge with nothing appended.
fn to_0_12_2(challenge: LoginChallenge) -> AuthChallenge {
    AuthChallenge {
        challenge,
        ceremony: ceremony(Some(&settings()), layout_of(Some(v0_12_2()))),
    }
}

fn signal(message: ManagementMessage) -> Vec<u8> {
    PeerSignal::SignInManagement {
        session_cid: CID,
        message,
    }
    .serialize_to_vector()
    .unwrap()
}

fn management(bytes: &[u8]) -> ManagementMessage {
    match PeerSignal::deserialize_from_vector(bytes).unwrap() {
        PeerSignal::SignInManagement {
            session_cid,
            message,
        } => {
            assert_eq!(session_cid, CID);
            message
        }
        other => panic!("not a management signal: {other:?}"),
    }
}

fn add_created() -> ManagementBegin {
    ManagementBegin {
        op: ManagementOp::AddCreatedSecurityKey {
            credential_id: b"cred-2".to_vec(),
            label: "YubiKey".into(),
        },
        step_up: start(),
        recovery_eks: Vec::new(),
    }
}

fn list() -> ManagementBegin {
    ManagementBegin {
        op: SignInManagementOp::ListCredentials.into(),
        step_up: start(),
        recovery_eks: Vec::new(),
    }
}

fn old_challenge() -> ManagementChallenge {
    ManagementChallenge {
        step_up: factors(),
        ceremony: None,
    }
}

fn finish() -> LoginFinish {
    LoginFinish {
        tags: vec![FactorTag {
            factor_id: 1,
            tag: [0x88; 32],
        }],
    }
}

#[test]
fn the_messages_a_0_12_2_peer_has_not_changed() {
    assert_eq!(
        start().serialize_to_vector().unwrap(),
        fixture!("login_start.bin")
    );
}

#[test]
fn a_0_12_2_client_is_sent_the_0_12_2_challenge() {
    let sent = to_0_12_2(factors());
    assert_eq!(
        sent.serialize_to_vector().unwrap(),
        fixture!("auth_challenge_factors.bin")
    );
    let legacy = to_0_12_2(LoginChallenge {
        server_nonce: [0x33; 32],
        body: ChallengeBody::Legacy { upgrade: None },
    });
    assert_eq!(
        legacy.serialize_to_vector().unwrap(),
        fixture!("auth_challenge_legacy.bin")
    );
}

#[test]
fn a_0_12_2_servers_challenge_reads_and_hashes_as_it_did() {
    let sent = read(fixture!("auth_challenge_factors.bin"), v0_12_2()).unwrap();
    assert_eq!(sent, to_0_12_2(factors()));
    assert_eq!(
        login_transcript(CID, &start(), &sent).as_bytes(),
        fixture!("login_transcript.bin")
    );
}

#[test]
fn a_current_client_and_server_append_the_ceremony_and_a_0_12_2_reader_skips_it() {
    let current = Some(*PROTOCOL_VERSION);
    let sent = AuthChallenge {
        challenge: factors(),
        ceremony: ceremony(Some(&settings()), layout_of(current)),
    };
    assert_eq!(
        sent.ceremony,
        Some(ChallengeCeremony {
            rp_id: Some("example.com".into())
        })
    );
    let bytes = sent.serialize_to_vector().unwrap();
    assert_eq!(read(&bytes, *PROTOCOL_VERSION).unwrap(), sent);
    // A 0.12.2 decoder reads the challenge and leaves the appended bytes.
    assert_eq!(
        LoginChallenge::deserialize_from_vector(&bytes).unwrap(),
        factors()
    );
}

#[test]
fn a_challenge_in_the_other_layout_than_the_servers_version_is_refused() {
    let current = AuthChallenge {
        challenge: factors(),
        ceremony: Some(ChallengeCeremony { rp_id: None }),
    };
    let bytes = current.serialize_to_vector().unwrap();
    let mismatched = read(&bytes, v0_12_2()).unwrap_err();
    assert_eq!(mismatched.code, ErrorCode::PqSignInMalformed);
    let missing = read(fixture!("auth_challenge_factors.bin"), *PROTOCOL_VERSION).unwrap_err();
    assert_eq!(missing.code, ErrorCode::PqSignInMalformed);
}

#[test]
fn a_0_12_2_clients_enrolment_reads_and_hashes_as_it_did() {
    let begin = management(fixture!("signal_begin_add_key.bin"));
    assert_eq!(begin, ManagementMessage::Begin(add_created()));
    assert_eq!(signal(begin), fixture!("signal_begin_add_key.bin"));
    let commit = management(fixture!("signal_commit_add_key.bin"));
    let expected = ManagementCommit {
        step_up: finish(),
        new_key_ek: Some(ek()),
        ceremony: None,
    };
    assert_eq!(commit, ManagementMessage::Commit(expected.clone()));
    let transcript = management_transcript(
        CID,
        &add_created(),
        &old_challenge(),
        &expected.key_binding(),
    );
    assert_eq!(
        transcript.as_bytes(),
        fixture!("management_transcript_add_key.bin")
    );
}

#[test]
fn a_0_12_2_client_is_sent_the_0_12_2_management_challenge() {
    let challenge = ManagementMessage::Challenge(old_challenge());
    assert_eq!(signal(challenge.clone()), fixture!("signal_challenge.bin"));
    assert_eq!(management(fixture!("signal_challenge.bin")), challenge);
}

#[test]
fn a_change_to_a_0_12_2_server_is_sent_as_0_12_2_sends_it() {
    let begin = ManagementMessage::Begin(list());
    assert!(sendable(&begin, Some(v0_12_2())).is_ok());
    assert_eq!(signal(begin), fixture!("signal_begin_list.bin"));
    let commit = ManagementCommit {
        step_up: finish(),
        new_key_ek: None,
        ceremony: None,
    };
    assert_eq!(
        signal(ManagementMessage::Commit(commit.clone())),
        fixture!("signal_commit_no_key.bin")
    );
    let transcript = management_transcript(CID, &list(), &old_challenge(), &commit.key_binding());
    assert_eq!(
        transcript.as_bytes(),
        fixture!("management_transcript_list.bin")
    );
}

/// A 0.12.2 server reads no enrolment whose credential is created after the challenge; the
/// client refuses before sending rather than leave the caller waiting on a dropped signal.
#[test]
fn a_client_does_not_enrol_a_key_it_creates_at_a_0_12_2_server() {
    let add = SignInManagementOp::AddSecurityKey {
        label: "YubiKey".into(),
    };
    let begin = ManagementMessage::Begin(ManagementBegin {
        op: add.into(),
        ..list()
    });
    let refused = sendable(&begin, Some(v0_12_2())).unwrap_err();
    assert_eq!(refused.code, ErrorCode::PqSignInUnavailable);
    assert!(sendable(&begin, Some(*PROTOCOL_VERSION)).is_ok());
}
