//! The epoch key schedule: fold the new root secret + the previous epoch's `init_secret` + the
//! transcript hash into an `epoch_secret`, then expand the per-epoch secrets.
//!
//! Chaining the previous `init_secret` into each epoch is what gives **post-compromise security**: an
//! attacker who learns one epoch's tree secrets still cannot derive the next epoch without also having
//! the fresh commit secret.

use crate::crypto::Secret;

/// The secrets derived for one epoch.
#[derive(Clone)]
pub struct EpochSecrets {
    /// Root of the epoch's key material (kept for derivation/debug; not used directly to encrypt).
    pub epoch_secret: Secret,
    /// Feeds the application-message ratchet (the per-epoch group encryption key).
    pub encryption_secret: Secret,
    /// MAC key over the transcript (proves all members reached the same epoch).
    pub confirmation_key: Secret,
    /// MAC key binding proposals/commits to this epoch.
    pub membership_key: Secret,
    /// Folded into the NEXT epoch's `epoch_secret` (post-compromise-security chaining).
    pub init_secret: Secret,
}

impl EpochSecrets {
    /// Genesis: epoch 0 starts from an all-zero `init_secret`.
    pub fn genesis(root_secret: &Secret, transcript_hash: &[u8; 32]) -> Self {
        Self::derive(root_secret, &[0u8; 32], transcript_hash)
    }

    /// Derive the epoch secrets from the new `root_secret`, the previous epoch's `init_secret`, and the
    /// confirmed transcript hash.
    pub fn derive(
        root_secret: &Secret,
        prev_init_secret: &Secret,
        transcript_hash: &[u8; 32],
    ) -> Self {
        // epoch_secret = KDF(root_secret || prev_init_secret || transcript_hash)
        let mut hasher = blake3::Hasher::new_derive_key("citadel-treekem-epoch-secret-v1");
        hasher.update(root_secret);
        hasher.update(prev_init_secret);
        hasher.update(transcript_hash);
        let epoch_secret = *hasher.finalize().as_bytes();

        EpochSecrets {
            encryption_secret: expand(&epoch_secret, "encryption"),
            confirmation_key: expand(&epoch_secret, "confirmation"),
            membership_key: expand(&epoch_secret, "membership"),
            init_secret: expand(&epoch_secret, "init"),
            epoch_secret,
        }
    }
}

/// Domain-separated expansion of a labeled sub-secret from the epoch secret.
fn expand(epoch_secret: &Secret, label: &str) -> Secret {
    let context = format!("citadel-treekem-key-schedule-{label}-v1");
    blake3::derive_key(&context, epoch_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_separated() {
        let root = [5u8; 32];
        let th = [7u8; 32];
        let a = EpochSecrets::genesis(&root, &th);
        let b = EpochSecrets::genesis(&root, &th);
        assert_eq!(a.encryption_secret, b.encryption_secret, "deterministic");
        // sub-secrets are domain-separated (all distinct)
        let set = [
            a.encryption_secret,
            a.confirmation_key,
            a.membership_key,
            a.init_secret,
            a.epoch_secret,
        ];
        for i in 0..set.len() {
            for j in (i + 1)..set.len() {
                assert_ne!(set[i], set[j], "sub-secrets {i},{j} must differ");
            }
        }
    }

    #[test]
    fn different_root_or_init_changes_epoch() {
        let th = [0u8; 32];
        let base = EpochSecrets::genesis(&[1u8; 32], &th);
        let diff_root = EpochSecrets::genesis(&[2u8; 32], &th);
        let diff_init = EpochSecrets::derive(&[1u8; 32], &[9u8; 32], &th);
        assert_ne!(base.epoch_secret, diff_root.epoch_secret);
        assert_ne!(base.epoch_secret, diff_init.epoch_secret);
    }
}
