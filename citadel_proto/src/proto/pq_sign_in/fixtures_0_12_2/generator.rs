//! Writes the 0.12.2 (SDK f419b95e) encodings of the sign-in messages, and the transcripts both
//! sides hash over them, as golden fixtures. Run from the f419b95e tree only.
use citadel_proto::prelude::PeerSignal;
use citadel_types::auth::{FactorKind, SignInManagementOp};
use citadel_user::auth::pq::kem::{FactorKeypair, FactorSeed, KemCiphertext, SEED_LEN};
use citadel_user::auth::pq::messages::*;
use citadel_user::auth::pq::record::KsfParams;
use citadel_user::auth::pq::{login_transcript, management_transcript};
use citadel_user::serialization::SyncIO;

const CID: u64 = 7;

fn ct(fill: u8) -> KemCiphertext {
    KemCiphertext::try_from(vec![fill; 1568]).unwrap()
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
            ksf: KsfParams {
                mem_kib: 19 * 1024,
                iterations: 2,
                lanes: 1,
            },
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

fn signal(message: ManagementMessage) -> Vec<u8> {
    PeerSignal::SignInManagement {
        session_cid: CID,
        message,
    }
    .serialize_to_vector()
    .unwrap()
}

fn main() {
    let out = std::path::PathBuf::from(std::env::args().nth(1).expect("out dir"));
    std::fs::create_dir_all(&out).unwrap();
    let write = |name: &str, bytes: &[u8]| std::fs::write(out.join(name), bytes).unwrap();

    let ek = FactorKeypair::derive(&FactorSeed::new([0x77; SEED_LEN]))
        .unwrap()
        .encapsulation_key()
        .clone();
    let legacy = LoginChallenge {
        server_nonce: [0x33; 32],
        body: ChallengeBody::Legacy { upgrade: None },
    };
    let add = ManagementBegin {
        op: SignInManagementOp::AddSecurityKey {
            credential_id: b"cred-2".to_vec(),
            label: "YubiKey".into(),
        },
        step_up: start(),
        recovery_eks: Vec::new(),
    };
    let list = ManagementBegin {
        op: SignInManagementOp::ListCredentials,
        step_up: start(),
        recovery_eks: Vec::new(),
    };
    let challenge = ManagementChallenge {
        step_up: factors(),
    };
    let finish = LoginFinish {
        tags: vec![FactorTag {
            factor_id: 1,
            tag: [0x88; 32],
        }],
    };

    write("login_start.bin", &start().serialize_to_vector().unwrap());
    write("auth_challenge_factors.bin", &factors().serialize_to_vector().unwrap());
    write("auth_challenge_legacy.bin", &legacy.serialize_to_vector().unwrap());
    write(
        "login_transcript.bin",
        login_transcript(CID, &start(), &factors()).as_bytes(),
    );
    write("signal_begin_add_key.bin", &signal(ManagementMessage::Begin(add.clone())));
    write("signal_begin_list.bin", &signal(ManagementMessage::Begin(list.clone())));
    write(
        "signal_challenge.bin",
        &signal(ManagementMessage::Challenge(challenge.clone())),
    );
    write(
        "signal_commit_add_key.bin",
        &signal(ManagementMessage::Commit(ManagementCommit {
            step_up: finish.clone(),
            new_key_ek: Some(ek.clone()),
        })),
    );
    write(
        "signal_commit_no_key.bin",
        &signal(ManagementMessage::Commit(ManagementCommit {
            step_up: finish,
            new_key_ek: None,
        })),
    );
    write(
        "management_transcript_add_key.bin",
        management_transcript(CID, &add, &challenge, Some(&ek)).as_bytes(),
    );
    write(
        "management_transcript_list.bin",
        management_transcript(CID, &list, &challenge, None).as_bytes(),
    );
    write("new_key_ek.bin", ek.as_bytes());
}
