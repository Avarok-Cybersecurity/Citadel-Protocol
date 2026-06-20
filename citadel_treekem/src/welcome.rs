//! Welcome: bootstraps a freshly-added member into the current epoch.
//!
//! The committer sends the joiner a public snapshot of the group (`GroupInfo`) plus a sealed payload —
//! the path secret at the lowest node where the joiner's path meets the committer's re-keyed path, and
//! the previous epoch's `init_secret` — so the joiner can ratchet up to the same root secret and run the
//! identical key schedule. The payload is HPKE-sealed to the joiner's leaf KEM key, so the relay can't
//! read it.

use crate::path::HpkeCiphertext;
use crate::tree::ratchet_tree::RatchetTree;
use serde::{Deserialize, Serialize};

/// Public snapshot of the group the joiner needs to reconstruct its view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupInfo {
    /// The (public) ratchet tree, including the joiner's just-inserted leaf.
    pub tree: RatchetTree,
    /// The epoch the joiner is entering.
    pub epoch: u64,
    /// The confirmed transcript hash at that epoch.
    pub transcript_hash: [u8; 32],
}

/// A bootstrap message for one joiner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    /// Public group snapshot.
    pub group_info: GroupInfo,
    /// The joiner's assigned leaf index.
    pub joiner_leaf_index: u32,
    /// The node where the joiner's direct path meets the committer's re-keyed path.
    pub lca_node: u32,
    /// HPKE-sealed `lca_path_secret(32) || prev_init_secret(32)` to the joiner's leaf KEM public key.
    pub sealed: HpkeCiphertext,
}
