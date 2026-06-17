//! Key packages: a joiner's published prekey so a committer can Add them without a round trip.

use crate::crypto::{node_keypair_from_path_secret, Secret};
use crate::tree::node::LeafNode;
use citadel_types::errors::Error;
use serde::{Deserialize, Serialize};

/// A joiner-published leaf the committer inserts on Add. (Long-term signature binding is added in the
/// hierarchy/identity milestone; for now the leaf carries the joiner's fresh ML-KEM public key.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackage {
    /// The joiner's leaf (identity + fresh KEM public key).
    pub leaf: LeafNode,
}

impl KeyPackage {
    /// Build a key package from a fresh leaf secret. The joiner keeps `leaf_secret` private; the
    /// resulting KEM keypair is reproducible from it (used to open the Welcome).
    pub fn generate(cid: u64, leaf_secret: &Secret) -> Result<Self, Error> {
        let (kem_public, _sk) = node_keypair_from_path_secret(leaf_secret)?;
        Ok(KeyPackage {
            leaf: LeafNode {
                cid,
                kem_public,
                sig_public: Vec::new(),
                leaf_index: 0, // assigned on insertion
                signature: Vec::new(),
            },
        })
    }
}
