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

/// A stored record names its factors' kinds by index, so those indices never move.
#[test]
fn stored_factor_kinds_keep_their_indices() {
    assert_eq!(bytes(&FactorKind::RecoveryCode), [2, 0, 0, 0]);
    assert_eq!(bytes(&FactorKind::RecoveryPhrase), [3, 0, 0, 0]);
    assert_eq!(TranscriptPurpose::Recover as u8, 3);
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
