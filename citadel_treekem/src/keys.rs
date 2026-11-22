//! Key packages: a joiner's published prekey so a committer can Add them without a round trip.

use crate::crypto::{node_keypair_from_path_secret, Secret};
use crate::tree::node::LeafNode;
use citadel_types::errors::Error;
use serde::{Deserialize, Serialize};

/// A joiner-published leaf the committer inserts on Add: the joiner's fresh KEM public key and the
/// verifying key its frames are signed with (see [`crate::signing`]). `signature` is left for the
/// application to bind the leaf to an account identity; this crate does not read it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackage {
    /// The joiner's leaf, keyed on the tree's suite ([`crate::crypto::CURRENT_SUITE`]).
    pub leaf: LeafNode,
}

impl KeyPackage {
    /// Build a key package from a fresh leaf secret. The joiner keeps `leaf_secret` private; the
    /// leaf's KEM keypair is reproducible from it (used to open the Welcome).
    pub fn generate(cid: u64, leaf_secret: &Secret) -> Result<Self, Error> {
        let (kem_public, _sk) = node_keypair_from_path_secret(leaf_secret)?;
        let (sig_public, _signing) = crate::signing::leaf_signature_keys(leaf_secret);
        Ok(KeyPackage {
            leaf: LeafNode {
                cid,
                kem_public,
                sig_public,
                leaf_index: 0, // assigned on insertion
                signature: Vec::new(),
            },
        })
    }
}
