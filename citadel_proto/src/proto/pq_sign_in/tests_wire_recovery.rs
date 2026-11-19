//! The recovery release on the wire: one gate, appended variants and fields only, and a 0.12.3
//! peer sent exactly the bytes it always was.

use super::manage::sendable;
use super::recover::server_recovers;
use crate::constants::{PROTOCOL_VERSION, RECOVERY_SINCE};
use citadel_io::ErrorCode;
use citadel_types::auth::FactorKind;
use citadel_user::auth::pq::kem::{EncapsulationKey, FactorKeypair, FactorSeed, SEED_LEN};
use citadel_user::auth::pq::messages::*;
use citadel_user::auth::pq::proof::TranscriptPurpose;
use citadel_user::auth::pq::record::KsfParams;
use citadel_user::serialization::SyncIO;
use embedded_semver::Semver;

fn version(patch: usize) -> u32 {
    Semver::new(0, 12, patch).to_u32().unwrap()
}

fn ek() -> EncapsulationKey {
    let keypair = FactorKeypair::derive(&FactorSeed::new([3u8; SEED_LEN])).unwrap();
    keypair.encapsulation_key().clone()
}

fn begin(op: ManagementOp, recovery_eks: Vec<EncapsulationKey>) -> ManagementMessage {
    ManagementMessage::Begin(ManagementBegin {
        op,
        step_up: LoginStart {
            username: "alice".into(),
            client_nonce: [1; 32],
            oprf_blinded: None,
            recovery: None,
            admission: None,
            resume: None,
        },
        recovery_eks,
    })
}

fn bytes<T: serde::Serialize + for<'de> serde::Deserialize<'de>>(value: &T) -> Vec<u8> {
    value.serialize_to_vector().unwrap()
}

/// Control: make `server_recovers` return true and the 0.12.3 assertions go red.
#[test]
fn only_a_server_at_the_recovery_release_is_asked_to_recover() {
    assert_eq!(RECOVERY_SINCE, (0, 12, 4));
    assert!(server_recovers(Some(*PROTOCOL_VERSION)));
    assert!(server_recovers(Some(version(4))));
    assert!(!server_recovers(Some(version(3))));
    assert!(!server_recovers(None));
}

#[test]
fn a_client_sends_no_password_or_phrase_change_to_an_older_server() {
    let set = begin(
        ManagementOp::SetPassword {
            oprf_blinded: vec![7; 32],
        },
        Vec::new(),
    );
    let phrase = begin(ManagementOp::RegenerateRecoveryPhrase, vec![ek()]);
    for message in [&set, &phrase] {
        let refused = sendable(message, Some(version(3))).unwrap_err();
        assert_eq!(refused.code, ErrorCode::RecoveryUnsupported);
        assert!(sendable(message, Some(*PROTOCOL_VERSION)).is_ok());
    }
    let list = begin(ManagementOp::ListCredentials, Vec::new());
    assert!(sendable(&list, Some(version(3))).is_ok());
}

/// The release appends; every index an older peer knows is unchanged.
#[test]
fn new_variants_are_appended() {
    assert_eq!(bytes(&FactorKind::RecoveryCode), [2, 0, 0, 0]);
    assert_eq!(bytes(&FactorKind::RecoveryPhrase), [3, 0, 0, 0]);
    assert_eq!(TranscriptPurpose::Recover as u8, 3);
    let add = ManagementOp::AddSecurityKey { label: "k".into() };
    assert_eq!(bytes(&add)[..4], [6, 0, 0, 0]);
    let set = ManagementOp::SetPassword {
        oprf_blinded: Vec::new(),
    };
    assert_eq!(bytes(&set)[..4], [7, 0, 0, 0]);
    assert_eq!(bytes(&ManagementOp::RegenerateRecoveryPhrase), [8, 0, 0, 0]);
    let phrase_replaced = ServerOutcome::RecoveryPhraseReplaced;
    assert_eq!(bytes(&ServerOutcome::PasswordSet), [6, 0, 0, 0]);
    assert_eq!(bytes(&phrase_replaced), [7, 0, 0, 0]);
}

/// A ceremony without a password change is 0.12.3's, byte for byte, so its transcripts are too.
#[test]
fn an_absent_password_change_appends_nothing() {
    let challenge = ManagementCeremony {
        rp_id: Some("example.com".into()),
        exclude_credentials: vec![vec![1, 2]],
        password: None,
    };
    let mut expected = bytes(&Some("example.com".to_string()));
    expected.extend(bytes(&vec![vec![1u8, 2]]));
    assert_eq!(bytes(&challenge), expected);

    let commit = CommitCeremony {
        new_key: None,
        password_ek: None,
    };
    assert_eq!(bytes(&commit), bytes(&Option::<NewSecurityKey>::None));

    let with_password = CommitCeremony {
        new_key: None,
        password_ek: Some(ek()),
    };
    let read = CommitCeremony::deserialize_from_vector(&bytes(&with_password)).unwrap();
    assert_eq!(read, with_password);
    let reply = RegReply {
        oprf_evaluated: vec![9; 32],
        salt_user: [1; 32],
        prf_eval_salt: [2; 32],
        ksf: KsfParams::FLOOR,
    };
    let with_reply = ManagementCeremony {
        password: Some(reply),
        ..challenge
    };
    let read = ManagementCeremony::deserialize_from_vector(&bytes(&with_reply)).unwrap();
    assert_eq!(read, with_reply);
}

/// A registration with no phrase is 0.12.3's `RegFinish`, byte for byte.
#[test]
fn a_registration_without_a_phrase_appends_nothing() {
    let finish = RegFinish {
        password_ek: ek(),
        recovery_eks: vec![ek()],
        recovery_phrase_ek: None,
    };
    let mut expected = bytes(&ek());
    expected.extend(bytes(&vec![ek()]));
    assert_eq!(bytes(&finish), expected);
}

/// Control: drop the version guard in `new_recovery` and the older server is sent a phrase.
#[test]
fn a_new_account_gets_a_phrase_only_from_a_server_that_recovers() {
    use super::register::new_recovery;
    use citadel_user::auth::pq::client::NewRecovery;
    let current = *PROTOCOL_VERSION;
    let phrase = new_recovery(current, Some("example.com"), "alice");
    assert!(matches!(
        phrase,
        NewRecovery::Phrase {
            canonical_domain: "example.com",
            username: "alice"
        }
    ));
    assert!(matches!(
        new_recovery(current, None, "alice"),
        NewRecovery::None
    ));
    let older = new_recovery(version(3), Some("example.com"), "alice");
    assert!(matches!(older, NewRecovery::Codes));
    assert!(matches!(
        new_recovery(version(3), None, "alice"),
        NewRecovery::Codes
    ));
}
