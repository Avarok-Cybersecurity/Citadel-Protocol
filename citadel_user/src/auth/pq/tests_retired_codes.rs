//! Recovery codes are retired: a stored record or a message that names one is refused by name,
//! and the kinds, changes and outcomes after the retired slots keep their encoding.

use super::kem::{FactorKeypair, FactorSeed, SEED_LEN};
use super::messages::{ManagementBegin, ManagementDone, ManagementOp, ServerOutcome};
use super::record::PqAuthRecord;
use super::tests::register;
use crate::serialization::SyncIO;
use citadel_io::{tokio, ErrorCode, NetworkError};
use citadel_types::auth::{FactorKind, RECOVERY_CODES_RETIRED};

/// The variant slot each retired variant held.
const FACTOR_KIND_CODE: u32 = 2;
const OP_REGENERATE_CODES: u32 = 4;
const OUTCOME_CODES_REPLACED: u32 = 5;

fn refused_by_name<T: std::fmt::Debug>(read: Result<T, NetworkError>) {
    let err = read.unwrap_err();
    assert_eq!(err.code, ErrorCode::DeserializationFailed);
    let message = err.into_string();
    assert!(message.contains(RECOVERY_CODES_RETIRED), "{message}");
}

/// Overwrites the little-endian `u32` at `at` (a bincode variant index).
fn with_index(mut bytes: Vec<u8>, at: usize, index: u32) -> Vec<u8> {
    bytes[at..at + 4].copy_from_slice(&index.to_le_bytes());
    bytes
}

/// A stored record whose recovery factor is in the code slot is refused; in the phrase slot it
/// reads. Control: make `RecoveryCodesRetired::deserialize` refuse with another message and the
/// three tests here fail on the name.
#[tokio::test]
async fn a_stored_record_with_a_recovery_code_is_refused() {
    let mut record = register("pw").await;
    let ek = FactorKeypair::derive(&FactorSeed::new([7; SEED_LEN]))
        .unwrap()
        .encapsulation_key()
        .clone();
    record.replace_recovery_phrase(ek, 2);
    let stored = record.serialize_to_vector().unwrap();
    let phrase = record.usable(FactorKind::RecoveryPhrase).next().unwrap();
    let factor = phrase.serialize_to_vector().unwrap();
    let at = stored
        .windows(factor.len())
        .position(|w| w == factor.as_slice())
        .expect("the record holds the factor's bytes");
    // A factor is its `u32` id, then its kind.
    let kind_at = at + 4;
    assert_eq!(stored[kind_at..kind_at + 4], 3u32.to_le_bytes());

    assert_eq!(
        PqAuthRecord::deserialize_from_vector(&stored).unwrap(),
        record
    );
    refused_by_name(PqAuthRecord::deserialize_from_vector(&with_index(
        stored,
        kind_at,
        FACTOR_KIND_CODE,
    )));
}

/// A management change naming the retired op is refused; the changes after it keep their slots.
#[test]
fn a_management_begin_regenerating_codes_is_refused() {
    let (begin, _) = super::client::ClientManagement::begin(
        "alice",
        citadel_types::auth::SignInManagementOp::ListCredentials,
        None,
        None,
    )
    .unwrap();
    let begin = ManagementBegin {
        op: ManagementOp::RegenerateRecoveryPhrase,
        ..begin
    };
    let bytes = begin.serialize_to_vector().unwrap();
    assert_eq!(bytes[..4], 7u32.to_le_bytes());
    assert_eq!(
        ManagementBegin::deserialize_from_vector(&bytes).unwrap(),
        begin
    );
    refused_by_name(ManagementBegin::deserialize_from_vector(&with_index(
        bytes,
        0,
        OP_REGENERATE_CODES,
    )));
}

/// An outcome naming the retired codes is refused; the outcomes after it keep their slots.
#[test]
fn an_outcome_of_replaced_codes_is_refused() {
    let done = ManagementDone::Done(ServerOutcome::PasswordSet);
    let bytes = done.serialize_to_vector().unwrap();
    assert_eq!(bytes[4..8], 6u32.to_le_bytes());
    assert_eq!(
        ManagementDone::deserialize_from_vector(&bytes).unwrap(),
        done
    );
    refused_by_name(ManagementDone::deserialize_from_vector(&with_index(
        bytes,
        4,
        OUTCOME_CODES_REPLACED,
    )));
}
