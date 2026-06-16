//! The ratchet tree: node model + array-based tree math.
//!
//! `math` holds the pure index relationships (parent/child/sibling/direct-path/copath). `node` holds
//! the per-node contents (a leaf's `LeafNode`, a parent's KEM public key + parent-hash, or a blank).

pub mod math;
pub mod node;
