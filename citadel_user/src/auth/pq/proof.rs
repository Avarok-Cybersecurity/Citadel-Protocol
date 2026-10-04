//! What turns a decapsulated secret into a sign-in: the transcript a proof is bound to, the
//! factor tag `HMAC-SHA3-256(K, label ‖ factor_id ‖ transcript_hash)`, and the session key that
//! mixes every proven factor's `K` into the channel's key schedule.

use super::kem::SharedSecret;
use citadel_types::auth::FactorId;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

/// The label of a sign-in tag (spec: `"citadel-auth-v1"`).
pub const AUTH_LABEL: &[u8] = b"citadel-auth-v1";
/// The label of an enrolment proof: the tag that shows the client holds a new key's
/// decapsulation key. Distinct from [`AUTH_LABEL`] so neither can stand in for the other.
pub const ENROL_LABEL: &[u8] = b"citadel-enrol-v1";

const TRANSCRIPT_LABEL: &[u8] = b"citadel-auth-transcript-v1";
const SESSION_KEY_INFO: &[u8] = b"citadel-auth-session-key-v1";

/// A factor tag.
pub type Tag = [u8; 32];

/// Which exchange a transcript belongs to, so a proof made for one is worthless in another.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
pub enum TranscriptPurpose {
    Login = 1,
    StepUp = 2,
}

/// SHA3-256 over everything both sides said in one exchange, length-framed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TranscriptHash([u8; 32]);

impl TranscriptHash {
    /// `parts` are the exchange's messages in order, each serialized once by the side that holds
    /// it; both sides hash the same bytes.
    pub fn new(purpose: TranscriptPurpose, cid: u64, parts: &[&[u8]]) -> Self {
        let mut hasher = Sha3_256::default();
        hasher.update(TRANSCRIPT_LABEL);
        hasher.update([purpose as u8]);
        hasher.update(cid.to_be_bytes());
        for part in parts {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        Self(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn tag_mac(
    k: &SharedSecret,
    label: &[u8],
    factor_id: FactorId,
    t: &TranscriptHash,
) -> Hmac<Sha3_256> {
    let mut mac = <Hmac<Sha3_256> as Mac>::new_from_slice(k.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(label);
    mac.update(&factor_id.to_be_bytes());
    mac.update(t.as_bytes());
    mac
}

/// The client's proof that it recovered `k` for `factor_id` in this transcript.
pub fn factor_tag(k: &SharedSecret, label: &[u8], factor_id: FactorId, t: &TranscriptHash) -> Tag {
    tag_mac(k, label, factor_id, t)
        .finalize()
        .into_bytes()
        .into()
}

/// The server's check of a presented tag, in constant time.
pub fn verify_factor_tag(
    k: &SharedSecret,
    label: &[u8],
    factor_id: FactorId,
    t: &TranscriptHash,
    presented: &Tag,
) -> bool {
    tag_mac(k, label, factor_id, t)
        .verify_slice(presented)
        .is_ok()
}

/// HKDF-SHA3-256 over the proven factors' secrets (in the order given), salted with the
/// transcript. Both sides add it to the session's pre-shared keys, so every key the session
/// ratchets to afterwards depends on the factors that admitted it.
pub fn session_key(secrets: &[&SharedSecret], t: &TranscriptHash) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(secrets.len() * 32));
    for secret in secrets {
        ikm.extend_from_slice(secret.as_bytes());
    }
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha3_256>::new(Some(t.as_bytes()), &ikm)
        .expand(SESSION_KEY_INFO, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA3-256 output length");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::pq::kem::{encapsulate, FactorKeypair, FactorSeed, SEED_LEN};

    fn secret() -> SharedSecret {
        let kp = FactorKeypair::derive(&FactorSeed::new([1u8; SEED_LEN])).unwrap();
        encapsulate(kp.encapsulation_key()).unwrap().1
    }

    #[test]
    fn a_tag_verifies_only_for_its_own_transcript_factor_and_label() {
        let k = secret();
        let t = TranscriptHash::new(TranscriptPurpose::Login, 7, &[b"start", b"challenge"]);
        let tag = factor_tag(&k, AUTH_LABEL, 1, &t);
        assert!(verify_factor_tag(&k, AUTH_LABEL, 1, &t, &tag));

        let other = TranscriptHash::new(TranscriptPurpose::Login, 7, &[b"start", b"challengf"]);
        assert!(!verify_factor_tag(&k, AUTH_LABEL, 1, &other, &tag));
        assert!(!verify_factor_tag(&k, AUTH_LABEL, 2, &t, &tag));
        assert!(!verify_factor_tag(&k, ENROL_LABEL, 1, &t, &tag));
        assert!(!verify_factor_tag(&secret(), AUTH_LABEL, 1, &t, &tag));
    }

    #[test]
    fn transcripts_differ_by_purpose_cid_and_framing() {
        let base = TranscriptHash::new(TranscriptPurpose::Login, 7, &[b"ab", b"c"]);
        assert_ne!(
            base,
            TranscriptHash::new(TranscriptPurpose::StepUp, 7, &[b"ab", b"c"])
        );
        assert_ne!(
            base,
            TranscriptHash::new(TranscriptPurpose::Login, 8, &[b"ab", b"c"])
        );
        assert_ne!(
            base,
            TranscriptHash::new(TranscriptPurpose::Login, 7, &[b"a", b"bc"])
        );
    }

    #[test]
    fn the_session_key_depends_on_every_secret_and_the_transcript() {
        let (a, b) = (secret(), secret());
        let t = TranscriptHash::new(TranscriptPurpose::Login, 1, &[b"x"]);
        let both = session_key(&[&a, &b], &t);
        assert_eq!(*both, *session_key(&[&a, &b], &t));
        assert_ne!(*both, *session_key(&[&a], &t));
        let t2 = TranscriptHash::new(TranscriptPurpose::Login, 1, &[b"y"]);
        assert_ne!(*both, *session_key(&[&a, &b], &t2));
    }
}
