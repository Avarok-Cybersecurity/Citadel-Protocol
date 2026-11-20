//! Key packages: a joiner's published prekey so a committer can Add them without a round trip.

use crate::crypto::{node_keypair_from_path_secret, Secret, CURRENT_SUITE, ROUND_3_SUITE};
use crate::tree::node::LeafNode;
use citadel_negotiation::frame::appended_field;
use citadel_types::errors::Error;
use serde::{Deserialize, Serialize};

/// A joiner-published leaf the committer inserts on Add. (Long-term signature binding is added in the
/// hierarchy/identity milestone; for now the leaf carries the joiner's fresh KEM public key.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackage {
    /// The joiner's leaf, keyed on the round-3 suite: the leaf a committer before 0.12.4 inserts.
    pub leaf: LeafNode,
    /// The joiner's ML-KEM-1024 leaf key, from the same leaf secret. Appended last, so a committer
    /// before 0.12.4 ignores it (bincode allows trailing bytes); a package from a joiner before
    /// 0.12.4 ends before it and reads as `None`.
    #[serde(default, deserialize_with = "appended_field")]
    pub current_kem_public: Option<Vec<u8>>,
}

impl KeyPackage {
    /// Build a key package from a fresh leaf secret. The joiner keeps `leaf_secret` private; both
    /// KEM keypairs are reproducible from it (used to open the Welcome).
    pub fn generate(cid: u64, leaf_secret: &Secret) -> Result<Self, Error> {
        let (kem_public, _sk) = node_keypair_from_path_secret(ROUND_3_SUITE, leaf_secret)?;
        let (current, _sk) = node_keypair_from_path_secret(CURRENT_SUITE, leaf_secret)?;
        Ok(KeyPackage {
            leaf: LeafNode {
                cid,
                kem_public,
                sig_public: Vec::new(),
                leaf_index: 0, // assigned on insertion
                signature: Vec::new(),
            },
            current_kem_public: Some(current),
        })
    }

    /// The leaf a committer of this release inserts: keyed on ML-KEM-1024 when the joiner offers
    /// it, on round 3 otherwise.
    pub fn leaf_to_insert(&self) -> LeafNode {
        let mut leaf = self.leaf.clone();
        if let Some(current) = &self.current_kem_public {
            leaf.kem_public = current.clone();
        }
        leaf
    }
}
