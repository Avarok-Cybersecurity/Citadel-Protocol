//! Sign-in messages in an older node's layout no longer read: each field is ordinary, so bytes
//! that end where an older node's message ended are refused rather than read as a default.

use super::challenge;
use citadel_io::ErrorCode;
use citadel_user::auth::pq::kem::{EncapsulationKey, FactorKeypair, FactorSeed, SEED_LEN};
use citadel_user::auth::pq::messages::*;
use citadel_user::auth::pq::record::KsfParams;
use citadel_user::serialization::SyncIO;
use serde::{Deserialize, Serialize};

fn bytes<T: Serialize + for<'de> Deserialize<'de>>(value: &T) -> Vec<u8> {
    value.serialize_to_vector().unwrap()
}

fn ek() -> EncapsulationKey {
    let keypair = FactorKeypair::derive(&FactorSeed::new([3u8; SEED_LEN])).unwrap();
    keypair.encapsulation_key().clone()
}

fn login_challenge() -> LoginChallenge {
    LoginChallenge {
        server_nonce: [5; 32],
        body: ChallengeBody::Legacy { upgrade: None },
    }
}

fn reply() -> RegReply {
    RegReply {
        oprf_evaluated: vec![9; 32],
        salt_user: [1; 32],
        prf_eval_salt: [2; 32],
        ksf: KsfParams::FLOOR,
    }
}

/// A 0.12.2 server's `AUTH_CHALLENGE` was the login challenge alone, with no relying party.
/// Control: read `AuthChallenge::ceremony` with `ok_or_default` (and give `ChallengeCeremony` a
/// default) and the older challenge reads.
#[test]
fn a_challenge_without_the_ceremony_is_refused_and_a_current_one_reads() {
    let refused = challenge::read(&bytes(&login_challenge())).unwrap_err();
    assert_eq!(refused.code, ErrorCode::PqSignInMalformed);

    let current = AuthChallenge {
        challenge: login_challenge(),
        ceremony: challenge::ceremony(None),
    };
    assert_eq!(challenge::read(&bytes(&current)).unwrap(), current);
}

/// A 0.12.2 management challenge was the step-up alone.
#[test]
fn a_management_challenge_without_the_ceremony_is_refused() {
    let older = ManagementChallenge::deserialize_from_vector(&bytes(&login_challenge()));
    assert_eq!(older.unwrap_err().code, ErrorCode::DeserializationFailed);

    let current = ManagementChallenge {
        step_up: login_challenge(),
        ceremony: ManagementCeremony {
            rp_id: Some("example.com".into()),
            exclude_credentials: vec![vec![1, 2]],
            password: None,
        },
    };
    let read = ManagementChallenge::deserialize_from_vector(&bytes(&current)).unwrap();
    assert_eq!(read, current);
}

/// The 0.12.2 shape of `ManagementCommit`: the new key's bare encapsulation key, no ceremony.
#[derive(Serialize, Deserialize)]
struct CommitOf0122 {
    step_up: LoginFinish,
    new_key_ek: Option<EncapsulationKey>,
}

#[test]
fn a_commit_in_the_0_12_2_layout_is_refused() {
    let older = CommitOf0122 {
        step_up: LoginFinish { tags: Vec::new() },
        new_key_ek: None,
    };
    let refused = ManagementCommit::deserialize_from_vector(&bytes(&older)).unwrap_err();
    assert_eq!(refused.code, ErrorCode::DeserializationFailed);

    let current = ManagementCommit {
        step_up: LoginFinish { tags: Vec::new() },
        ceremony: CommitCeremony {
            new_key: Some(NewSecurityKey {
                credential_id: vec![4; 16],
                ek: ek(),
            }),
            password_ek: None,
        },
    };
    let read = ManagementCommit::deserialize_from_vector(&bytes(&current)).unwrap();
    assert_eq!(read, current);
}

/// The 0.12.3 shapes of the ceremonies: no password change.
#[derive(Serialize, Deserialize)]
struct ManagementCeremonyOf0123 {
    rp_id: Option<String>,
    exclude_credentials: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct CommitCeremonyOf0123 {
    new_key: Option<NewSecurityKey>,
}

/// A ceremony that ends before its password change is an older node's, and is refused; a current
/// one reads with or without a password change.
#[test]
fn a_ceremony_without_its_password_change_is_refused() {
    let older = ManagementCeremonyOf0123 {
        rp_id: Some("example.com".into()),
        exclude_credentials: vec![vec![1, 2]],
    };
    let refused = ManagementCeremony::deserialize_from_vector(&bytes(&older)).unwrap_err();
    assert_eq!(refused.code, ErrorCode::DeserializationFailed);
    let older = CommitCeremonyOf0123 { new_key: None };
    let refused = CommitCeremony::deserialize_from_vector(&bytes(&older)).unwrap_err();
    assert_eq!(refused.code, ErrorCode::DeserializationFailed);

    for password in [None, Some(reply())] {
        let current = ManagementCeremony {
            rp_id: Some("example.com".into()),
            exclude_credentials: vec![vec![1, 2]],
            password,
        };
        let read = ManagementCeremony::deserialize_from_vector(&bytes(&current)).unwrap();
        assert_eq!(read, current);
    }
    for password_ek in [None, Some(ek())] {
        let current = CommitCeremony {
            new_key: None,
            password_ek,
        };
        let read = CommitCeremony::deserialize_from_vector(&bytes(&current)).unwrap();
        assert_eq!(read, current);
    }
}
