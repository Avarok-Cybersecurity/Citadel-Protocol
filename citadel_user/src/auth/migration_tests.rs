//! A hypothetical version 3 ("V2" of the post-quantum record), added the way the pattern says:
//! appended to the stored enum and reached through the same hook, at proof time, one way.

use super::{upgrade_at_proof, ProvenSignIn, VersionedAuthRecord};
use crate::auth::stored::{RetiredArgonContainer, POST_QUANTUM_VERSION};
use crate::auth::{DeclaredAuthenticationMode, PqAuthSide};
use crate::misc::AccountError;
use crate::serialization::SyncIO;
use citadel_io::ErrorCode;
use citadel_types::auth::FactorId;
use serde::{Deserialize, Serialize};

/// `StoredAuthMode` with a new version appended.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
enum StoredWithV2 {
    RetiredArgon {
        username: String,
        full_name: String,
        argon: RetiredArgonContainer,
    },
    Transient {
        username: String,
        full_name: String,
    },
    PostQuantum {
        username: String,
        full_name: String,
        side: PqAuthSide,
    },
    /// The new version: what the last sign-in proved with, which only a proof can supply.
    PostQuantumV2 {
        username: String,
        full_name: String,
        side: PqAuthSide,
        proved_with: Vec<FactorId>,
    },
}

const V2_VERSION: u32 = POST_QUANTUM_VERSION + 1;

impl VersionedAuthRecord for StoredWithV2 {
    type Proven = ProvenSignIn;

    fn version(&self) -> u32 {
        match self {
            Self::RetiredArgon { .. } => 0,
            Self::Transient { .. } => 1,
            Self::PostQuantum { .. } => POST_QUANTUM_VERSION,
            Self::PostQuantumV2 { .. } => V2_VERSION,
        }
    }

    fn migrate(&self, proven: &ProvenSignIn) -> Result<Option<Self>, AccountError> {
        match self {
            Self::PostQuantum {
                username,
                full_name,
                side,
            } => Ok(Some(Self::PostQuantumV2 {
                username: username.clone(),
                full_name: full_name.clone(),
                side: side.clone(),
                proved_with: proven.used.clone(),
            })),
            _ => Ok(None),
        }
    }
}

fn v1() -> DeclaredAuthenticationMode {
    DeclaredAuthenticationMode::PostQuantum {
        username: "carol".into(),
        full_name: "Carol".into(),
        side: PqAuthSide::Client,
    }
}

fn proven() -> ProvenSignIn {
    ProvenSignIn {
        used: vec![1, 4],
        now_ms: 9,
    }
}

#[test]
fn appending_a_version_leaves_every_record_already_written_readable() {
    let written = v1().serialize_to_vector().unwrap();
    let read = StoredWithV2::deserialize_from_vector(&written).unwrap();
    assert_eq!(read.version(), POST_QUANTUM_VERSION);
}

#[test]
fn a_v1_record_moves_to_v2_at_proof_time_and_then_stays() {
    let written = v1().serialize_to_vector().unwrap();
    let mut record = StoredWithV2::deserialize_from_vector(&written).unwrap();
    assert!(upgrade_at_proof(&mut record, &proven()).unwrap());
    let StoredWithV2::PostQuantumV2 { proved_with, .. } = &record else {
        panic!("not upgraded: {record:?}");
    };
    assert_eq!(proved_with, &vec![1, 4]);
    assert!(
        !upgrade_at_proof(&mut record, &proven()).unwrap(),
        "moved twice"
    );
    let saved = StoredWithV2::deserialize_from_vector(&record.serialize_to_vector().unwrap());
    assert_eq!(saved.unwrap(), record);
}

/// A migration that steps down a version: refused, or a record could be downgraded.
struct Downgrade(u32);

impl VersionedAuthRecord for Downgrade {
    type Proven = ProvenSignIn;

    fn version(&self) -> u32 {
        self.0
    }

    fn migrate(&self, _proven: &ProvenSignIn) -> Result<Option<Self>, AccountError> {
        Ok((self.0 == 2).then_some(Downgrade(1)))
    }
}

#[test]
fn a_step_that_does_not_raise_the_version_is_refused() {
    let mut record = Downgrade(2);
    let refused = upgrade_at_proof(&mut record, &proven()).unwrap_err();
    assert_eq!(refused.code, ErrorCode::PqSignInMalformed);
    assert_eq!(record.0, 2, "the record was changed");
}

#[test]
fn todays_records_are_current() {
    let mut record = v1();
    assert!(!upgrade_at_proof(&mut record, &proven()).unwrap());
    assert_eq!(record, v1());
}
