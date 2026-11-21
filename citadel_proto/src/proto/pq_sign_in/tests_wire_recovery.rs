//! Recovery on the wire: a new account is given the phrase or nothing, never codes, and a stored
//! record's factor kinds keep their indices, the retired code kind's slot refused by name.

use super::register::new_recovery;
use crate::constants::{PROTOCOL_VERSION, RECOVERY_SINCE};
use crate::proto::version_gate::check_peer_protocol_version;
use citadel_io::ErrorCode;
use citadel_types::auth::{FactorKind, RECOVERY_CODES_RETIRED};
use citadel_user::auth::pq::client::NewRecovery;
use citadel_user::auth::pq::proof::TranscriptPurpose;
use citadel_user::serialization::SyncIO;
use embedded_semver::Semver;

fn bytes<T: serde::Serialize + for<'de> serde::Deserialize<'de>>(value: &T) -> Vec<u8> {
    value.serialize_to_vector().unwrap()
}

/// A server below the recovery release (which would have been given codes, and answered a phrase
/// with a decoy) is refused at the handshake; this node is admitted.
#[test]
fn a_server_below_the_recovery_release_is_refused_by_name() {
    let (major, minor, patch) = RECOVERY_SINCE;
    assert!(patch > 0, "the release has a predecessor in its minor");
    let older = Semver::new(major.into(), minor.into(), (patch - 1).into())
        .to_u32()
        .unwrap();
    let refused = check_peer_protocol_version(older).unwrap_err();
    assert_eq!(refused.code, ErrorCode::ProtocolVersionUnsupported);
    assert!(check_peer_protocol_version(*PROTOCOL_VERSION).is_ok());
}

/// A stored record names its factors' kinds by index, so those indices never move, and the
/// retired code kind's index is refused by name.
#[test]
fn stored_factor_kinds_keep_their_indices() {
    let retired = FactorKind::deserialize_from_vector(&[2, 0, 0, 0]).unwrap_err();
    assert_eq!(retired.code, ErrorCode::DeserializationFailed);
    assert!(retired.into_string().contains(RECOVERY_CODES_RETIRED));
    assert_eq!(bytes(&FactorKind::RecoveryPhrase), [3, 0, 0, 0]);
    assert_eq!(
        FactorKind::deserialize_from_vector(&[3, 0, 0, 0]).unwrap(),
        FactorKind::RecoveryPhrase
    );
    assert_eq!(TranscriptPurpose::Recover as u8, 3);
}

#[test]
fn a_new_account_gets_a_phrase_given_a_domain_and_nothing_without_one() {
    let phrase = new_recovery(Some("example.com"), "alice");
    assert!(matches!(
        phrase,
        NewRecovery::Phrase {
            canonical_domain: "example.com",
            username: "alice"
        }
    ));
    assert!(matches!(new_recovery(None, "alice"), NewRecovery::None));
}
