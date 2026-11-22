//! Proposals + commits: a commit bundles the membership changes (Add/Remove) with the path re-key, so
//! every member applies the *same* changes to their tree before ratcheting — keeping all views in sync.

use crate::path::UpdatePath;
use crate::tree::node::LeafNode;
use serde::{Deserialize, Serialize};

/// A membership change applied as part of a commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proposal {
    /// Insert `leaf` at `leaf_index` (the committer-assigned slot). Encoded exactly as the
    /// single-field key package earlier releases carry here, so every release reads it.
    Add { leaf: LeafNode, leaf_index: u32 },
    /// Blank the leaf (and its path) at `leaf_index`.
    Remove { leaf_index: u32 },
    /// The committer, at `leaf_index`, replaces its own leaf: the commit's path carries the new
    /// leaf's keys. Unlike a pure re-key, it keeps the epoch it leaves readable, so what the other
    /// members sealed before they saw it is not lost.
    Update { leaf_index: u32 },
}

/// A commit: zero or more membership proposals followed by the committer's path re-key. The whole commit
/// is bound into the transcript hash, so a tampered/reordered commit yields a divergent epoch secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    pub proposals: Vec<Proposal>,
    pub path: UpdatePath,
}
