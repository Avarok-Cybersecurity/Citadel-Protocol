//! Decentralized Hierarchy Encryption (DHE): a command-hierarchy overlay where a superior can
//! cryptographically read everything in its subtree, transitively — while staying zero-trust to the
//! relay. Built as a one-way KDF/KEM key-tree (post-quantum via BLAKE3 + ML-KEM), behind the
//! [`HierarchyScheme`] trait so an audited lattice HIBE can be slotted in later (a deferred phase).
//!
//! ## How it works
//! Each member occupies a node in the command tree, identified by a [`CommandPath`]
//! (e.g. `/HQ/Bn1/Co-A/Plt-2`). A node's secret is derived one-way from its parent's:
//! `node_secret(child) = BLAKE3_keyed(parent_secret, child_segment)`. So an **ancestor** can derive
//! every descendant secret (read **down** the chain), but a subordinate learns nothing about an
//! ancestor or sibling secret (cannot read **up**). Each node's ML-KEM keypair is deterministically
//! seeded from its secret. A sender encrypts each message's content key to **its own** node's public
//! key, so exactly the sender and its ancestors can recover it.

use crate::crypto::{self, Secret};
use crate::path::HpkeCiphertext;
use citadel_types::errors::Error;
// `CommandPath`/`ReadPolicy` live in `citadel_types` (the lower crate) so the proto/SDK API can name
// them; re-exported here so `citadel_treekem::hierarchy::{CommandPath, ReadPolicy}` still resolves.
pub use citadel_types::proto::{CommandPath, ReadPolicy};
use serde::{Deserialize, Serialize};

/// The hierarchy crypto interface (swappable: KDF/KEM tree now, an audited HIBE later).
pub trait HierarchyScheme {
    /// Derive a descendant node's secret from an ancestor's secret. Requires `ancestor` to be an
    /// ancestor of (or equal to) `descendant`.
    fn derive_descendant_secret(
        &self,
        ancestor_secret: &Secret,
        ancestor: &CommandPath,
        descendant: &CommandPath,
    ) -> Result<Secret, Error>;

    /// The ML-KEM `(public, secret)` keypair for a node, from its node secret.
    fn node_keypair(&self, node_secret: &Secret) -> Result<(Vec<u8>, Vec<u8>), Error>;
}

/// The shipped scheme: a one-way BLAKE3 key chain + deterministic ML-KEM per node. Post-quantum and
/// audit-friendly (no lattice trapdoors).
#[derive(Clone, Copy, Default)]
pub struct KdfKemTree;

impl HierarchyScheme for KdfKemTree {
    fn derive_descendant_secret(
        &self,
        ancestor_secret: &Secret,
        ancestor: &CommandPath,
        descendant: &CommandPath,
    ) -> Result<Secret, Error> {
        if !ancestor.is_ancestor_of(descendant) {
            return Err(Error::generic(
                "DHE: requested node is not in the holder's subtree (cannot read up/across)",
            ));
        }
        let mut secret = *ancestor_secret;
        for segment in &descendant.0[ancestor.0.len()..] {
            // node_secret(child) = BLAKE3_keyed(parent_secret, child_segment)
            secret = *blake3::keyed_hash(&secret, segment.as_bytes()).as_bytes();
        }
        Ok(secret)
    }

    fn node_keypair(&self, node_secret: &Secret) -> Result<(Vec<u8>, Vec<u8>), Error> {
        use sha3::{Digest, Sha3_512};
        let out = Sha3_512::new()
            .chain_update(node_secret)
            .chain_update(b"citadel-dhe-kem-seed-v1")
            .finalize();
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&out);
        citadel_pqcrypto::kem_keypair_from_seed(&seed)
    }
}

/// A hierarchy-aware encrypted message. The relay forwards it verbatim and can read none of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DheEnvelope {
    /// The sender's command path (so ancestors know which subtree key to derive).
    pub sender_path: CommandPath,
    /// AEAD of the plaintext under a fresh per-message content key (fixed nonce — the key is single-use).
    pub body: Vec<u8>,
    /// Hierarchy wrap: the content key HPKE-sealed to the sender's own node public key (sender +
    /// ancestors can open).
    pub wrap_hier: HpkeCiphertext,
    /// Flat-group wrap (present only in [`ReadPolicy::BroadcastAudit`]): the content key AEAD'd under
    /// the flat group epoch key (any group member can open).
    pub wrap_flat: Option<FlatWrap>,
}

/// The content key encrypted under the flat group epoch key (with its nonce, since the flat key is
/// reused across messages).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatWrap {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

const CONTENT_NONCE: [u8; 12] = [0u8; 12];

impl DheEnvelope {
    /// Seal a message. `sender_node_secret` is the sender's own node secret (held since assignment);
    /// `flat_group_key` is the flat CGKA epoch key, required iff `policy == BroadcastAudit`.
    pub fn seal<S: HierarchyScheme>(
        scheme: &S,
        sender_path: &CommandPath,
        sender_node_secret: &Secret,
        flat_group_key: Option<&Secret>,
        policy: ReadPolicy,
        content_key: &Secret,
        plaintext: &[u8],
    ) -> Result<Self, Error> {
        // Body under the single-use content key.
        let body = crypto::sym_seal(content_key, &CONTENT_NONCE, plaintext)?;

        // Hierarchy wrap: seal the content key to the sender's own node public key.
        let (node_pk, _node_sk) = scheme.node_keypair(sender_node_secret)?;
        let (kem_ct, aead_ct) = crypto::hpke_seal(&node_pk, content_key)?;
        let wrap_hier = HpkeCiphertext { kem_ct, aead_ct };

        // Flat wrap (broadcast+audit only).
        let wrap_flat = match policy {
            ReadPolicy::SuperiorOnly => None,
            ReadPolicy::BroadcastAudit => {
                let flat = flat_group_key.ok_or_else(|| {
                    Error::generic("DHE: BroadcastAudit requires the flat group key")
                })?;
                // Nonce derived from the unique content key, so reuse of the flat key is safe. Stored in
                // the wrap because a recipient needs it before it has recovered the content key.
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(
                    &blake3::derive_key("citadel-dhe-flat-nonce-v1", content_key)[..12],
                );
                let ciphertext = crypto::sym_seal(flat, &nonce, content_key)?;
                Some(FlatWrap { nonce, ciphertext })
            }
        };

        Ok(DheEnvelope {
            sender_path: sender_path.clone(),
            body,
            wrap_hier,
            wrap_flat,
        })
    }

    /// Open as a **superior** (or the sender): derive the sender node's secret from `my_node_secret`
    /// (requires `my_path` to be an ancestor of the sender), recover the content key, decrypt.
    pub fn open_as_superior<S: HierarchyScheme>(
        &self,
        scheme: &S,
        my_path: &CommandPath,
        my_node_secret: &Secret,
    ) -> Result<Vec<u8>, Error> {
        let sender_secret =
            scheme.derive_descendant_secret(my_node_secret, my_path, &self.sender_path)?;
        let (_pk, sk) = scheme.node_keypair(&sender_secret)?;
        let content_key_bytes =
            crypto::hpke_open(&self.wrap_hier.kem_ct, &self.wrap_hier.aead_ct, &sk)?;
        self.decrypt_body(&content_key_bytes)
    }

    /// Open as an ordinary flat-group member (only possible in `BroadcastAudit` mode).
    pub fn open_as_member(&self, flat_group_key: &Secret) -> Result<Vec<u8>, Error> {
        let wrap = self
            .wrap_flat
            .as_ref()
            .ok_or_else(|| Error::generic("DHE: message has no flat wrap (superior-only mode)"))?;
        let content_key_bytes = crypto::sym_open(flat_group_key, &wrap.nonce, &wrap.ciphertext)?;
        self.decrypt_body(&content_key_bytes)
    }

    fn decrypt_body(&self, content_key_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        if content_key_bytes.len() != crypto::SECRET_LEN {
            return Err(Error::generic(
                "DHE: recovered content key has wrong length",
            ));
        }
        let mut content_key: Secret = [0u8; crypto::SECRET_LEN];
        content_key.copy_from_slice(content_key_bytes);
        crypto::sym_open(&content_key, &CONTENT_NONCE, &self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_SECRET: Secret = [7u8; 32];

    fn secret_for(path: &CommandPath) -> Secret {
        KdfKemTree
            .derive_descendant_secret(&ROOT_SECRET, &CommandPath::root(), path)
            .unwrap()
    }

    fn seal(sender: &str, policy: ReadPolicy, flat: Option<&Secret>, msg: &[u8]) -> DheEnvelope {
        let path = CommandPath::parse(sender);
        let secret = secret_for(&path);
        DheEnvelope::seal(&KdfKemTree, &path, &secret, flat, policy, &[0x42; 32], msg).unwrap()
    }

    fn open_as(env: &DheEnvelope, reader: &str) -> Result<Vec<u8>, Error> {
        let path = CommandPath::parse(reader);
        env.open_as_superior(&KdfKemTree, &path, &secret_for(&path))
    }

    #[test]
    fn superior_and_root_read_subordinate() {
        let env = seal(
            "/HQ/Bn1/Co-A/Plt-2",
            ReadPolicy::SuperiorOnly,
            None,
            b"sitrep",
        );
        // The sender reads its own message.
        assert_eq!(open_as(&env, "/HQ/Bn1/Co-A/Plt-2").unwrap(), b"sitrep");
        // Every superior up the chain reads it.
        assert_eq!(open_as(&env, "/HQ/Bn1/Co-A").unwrap(), b"sitrep");
        assert_eq!(open_as(&env, "/HQ/Bn1").unwrap(), b"sitrep");
        assert_eq!(open_as(&env, "/HQ").unwrap(), b"sitrep");
        // The root authority reads any subtree.
        assert_eq!(
            env.open_as_superior(&KdfKemTree, &CommandPath::root(), &ROOT_SECRET)
                .unwrap(),
            b"sitrep",
        );
    }

    #[test]
    fn sibling_and_subordinate_cannot_read() {
        let env = seal(
            "/HQ/Bn1/Co-A/Plt-2",
            ReadPolicy::SuperiorOnly,
            None,
            b"sitrep",
        );
        // A sibling company cannot read another company's traffic.
        assert!(open_as(&env, "/HQ/Bn1/Co-B").is_err());
        // A sibling platoon cannot.
        assert!(open_as(&env, "/HQ/Bn1/Co-A/Plt-1").is_err());

        // A subordinate cannot read a superior's message (no upward derivation).
        let from_superior = seal("/HQ/Bn1", ReadPolicy::SuperiorOnly, None, b"orders");
        assert!(open_as(&from_superior, "/HQ/Bn1/Co-A/Plt-2").is_err());
    }

    #[test]
    fn kdf_chain_is_one_way() {
        let child = CommandPath::parse("/HQ/Bn1/Co-A");
        let parent = CommandPath::parse("/HQ/Bn1");
        let child_secret = secret_for(&child);
        // You cannot derive an ancestor secret from a descendant secret.
        assert!(KdfKemTree
            .derive_descendant_secret(&child_secret, &child, &parent)
            .is_err());
        // A child secret is independent of a sibling's.
        let sib_a = secret_for(&CommandPath::parse("/HQ/Bn1/Co-A"));
        let sib_b = secret_for(&CommandPath::parse("/HQ/Bn1/Co-B"));
        assert_ne!(sib_a, sib_b);
    }

    #[test]
    fn server_cannot_read_superior_only() {
        let env = seal(
            "/HQ/Bn1/Co-A",
            ReadPolicy::SuperiorOnly,
            None,
            b"classified",
        );
        // No flat wrap, so a holder of no command secret (the relay) has nothing to open.
        assert!(env.wrap_flat.is_none());
        assert!(env.open_as_member(&[0u8; 32]).is_err());
        // An arbitrary non-ancestor secret can't open the hierarchy wrap.
        assert!(open_as(&env, "/Other/Unit").is_err());
    }

    #[test]
    fn broadcast_audit_dual_wrap() {
        let flat = [3u8; 32];
        let env = seal(
            "/HQ/Bn1/Co-A/Plt-2",
            ReadPolicy::BroadcastAudit,
            Some(&flat),
            b"net traffic",
        );
        // An ordinary group member reads via the flat group key.
        assert_eq!(env.open_as_member(&flat).unwrap(), b"net traffic");
        // A superior additionally reads via the hierarchy (audit capability).
        assert_eq!(open_as(&env, "/HQ/Bn1").unwrap(), b"net traffic");
        // A wrong flat key fails.
        assert!(env.open_as_member(&[0u8; 32]).is_err());
    }

    #[test]
    fn promotion_grants_subtree_access() {
        let env = seal(
            "/HQ/Bn1/Co-A/Plt-2",
            ReadPolicy::SuperiorOnly,
            None,
            b"sitrep",
        );
        // As Co-B, no access.
        assert!(open_as(&env, "/HQ/Bn1/Co-B").is_err());
        // Promoted to Bn1 (handed the Bn1 node secret), the same person now reads the whole subtree.
        assert_eq!(open_as(&env, "/HQ/Bn1").unwrap(), b"sitrep");
    }
}
