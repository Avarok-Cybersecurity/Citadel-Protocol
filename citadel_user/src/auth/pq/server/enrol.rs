//! The proof of possession a security key being added gives, after the step-up.

use super::change::Change;
use crate::auth::pq::kem::{encapsulate, EncapsulationKey, SharedSecret};
use crate::auth::pq::messages::{transcript_bytes, EnrolChallenge, EnrolProof};
use crate::auth::pq::proof::{verify_factor_tag, TranscriptHash, TranscriptPurpose, ENROL_LABEL};
use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};

/// The proof of possession a key being added must give.
pub(super) fn enrol(
    cid: u64,
    transcript: TranscriptHash,
    ek: EncapsulationKey,
    credential_id: Vec<u8>,
    label: String,
) -> Result<super::manage::CommitStep, AccountError> {
    let (ct, k) = encapsulate(&ek)?;
    let challenge = EnrolChallenge { ct };
    let transcript = TranscriptHash::new(
        TranscriptPurpose::StepUp,
        cid,
        &[transcript.as_bytes(), &transcript_bytes(&challenge)],
    );
    let pending = PendingEnrol {
        key: NewKey {
            ek,
            credential_id,
            label,
        },
        k,
        transcript,
    };
    Ok(super::manage::CommitStep::Enrol(challenge, pending))
}

pub struct NewKey {
    pub(super) ek: EncapsulationKey,
    pub(super) credential_id: Vec<u8>,
    pub(super) label: String,
}

/// A key waiting for its proof of possession.
pub struct PendingEnrol {
    key: NewKey,
    k: SharedSecret,
    transcript: TranscriptHash,
}

impl PendingEnrol {
    /// Nobody enrols a key they do not hold: the tag needs the key's decapsulation of the
    /// ciphertext the server just made.
    pub fn finish(self, proof: &EnrolProof) -> Result<Change, AccountError> {
        if verify_factor_tag(&self.k, ENROL_LABEL, 0, &self.transcript, &proof.tag) {
            Ok(Change::AddKey(self.key))
        } else {
            Err(error!(ErrorCode::PqSignInFailed))
        }
    }
}
