//! Per-node contents of the ratchet tree.

use serde::{Deserialize, Serialize};

/// A member's leaf: their Citadel identity (`cid`), current ML-KEM encapsulation public key,
/// long-term signature public key, leaf position, and a signature binding `(cid, kem_public,
/// sig_public, leaf_index, ...)` so a malicious relay can't forge or relocate a member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafNode {
    /// The member's Citadel client id (== their identity in the group).
    pub cid: u64,
    /// ML-KEM encapsulation (public) key for this leaf — recipients encapsulate path secrets to it.
    pub kem_public: Vec<u8>,
    /// The member's long-term signature verifying key (ML-DSA / Falcon).
    pub sig_public: Vec<u8>,
    /// This leaf's index in `0..n`.
    pub leaf_index: u32,
    /// Signature by the member's long-term key over this leaf's contents.
    pub signature: Vec<u8>,
}

/// One slot of the `2n-1` ratchet-tree array.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Node {
    /// A member's leaf.
    Leaf(LeafNode),
    /// An internal node: the KEM public key derived from this node's path secret, the parent-hash
    /// chaining the subtree shape, and `unmerged_leaves` — leaves added since this node was last
    /// re-keyed, whose secrets it does not yet cover (so encryptors must also target them directly).
    Parent {
        /// KEM public key derived from the node's path secret.
        kem_public: Vec<u8>,
        /// Hash binding this node to its child subtree shape.
        parent_hash: [u8; 32],
        /// Leaves added under this node since it was last re-keyed.
        unmerged_leaves: Vec<u32>,
    },
    /// An empty slot: a removed member, or an unpopulated part of a non-full tree.
    #[default]
    Blank,
}

impl Node {
    /// Whether this slot is blank.
    pub fn is_blank(&self) -> bool {
        matches!(self, Node::Blank)
    }

    /// The KEM public key at this node, if any (leaves and re-keyed parents have one; blanks don't).
    pub fn kem_public(&self) -> Option<&[u8]> {
        match self {
            Node::Leaf(leaf) => Some(&leaf.kem_public),
            Node::Parent { kem_public, .. } => Some(kem_public),
            Node::Blank => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_helpers_and_roundtrip() {
        let leaf = Node::Leaf(LeafNode {
            cid: 42,
            kem_public: vec![1, 2, 3],
            sig_public: vec![4, 5],
            leaf_index: 0,
            signature: vec![6],
        });
        assert!(!leaf.is_blank());
        assert_eq!(leaf.kem_public(), Some(&[1u8, 2, 3][..]));
        assert!(Node::Blank.is_blank());
        assert_eq!(Node::Blank.kem_public(), None);

        // bincode round-trip (the wire format)
        let bytes = bincode::serialize(&leaf).unwrap();
        let back: Node = bincode::deserialize(&bytes).unwrap();
        assert_eq!(leaf, back);
    }
}
