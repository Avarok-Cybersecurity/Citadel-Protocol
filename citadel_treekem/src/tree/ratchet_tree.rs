//! The ratchet tree array + the `resolution` operation (which drives path encryption).

use super::math::*;
use super::node::{LeafNode, Node};
use serde::{Deserialize, Serialize};

/// The ratchet tree: a `2n-1` array of [`Node`]s.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetTree {
    pub nodes: Vec<Node>,
}

impl RatchetTree {
    /// Build a tree from a full set of leaves; all internal nodes start blank.
    pub fn from_leaves(leaves: Vec<LeafNode>) -> Self {
        let n = leaves.len() as u32;
        let width = node_width(n) as usize;
        let mut nodes = vec![Node::Blank; width];
        for (i, leaf) in leaves.into_iter().enumerate() {
            nodes[leaf_to_node(i as u32) as usize] = Node::Leaf(leaf);
        }
        Self { nodes }
    }

    /// Number of leaves.
    pub fn num_leaves(&self) -> u32 {
        if self.nodes.is_empty() {
            0
        } else {
            (self.nodes.len() as u32).div_ceil(2)
        }
    }

    /// Borrow node `x`.
    pub fn get(&self, x: NodeIndex) -> &Node {
        &self.nodes[x as usize]
    }

    /// Replace node `x`.
    pub fn set(&mut self, x: NodeIndex, node: Node) {
        self.nodes[x as usize] = node;
    }

    /// The **resolution** of node `x`: the ordered, minimal set of non-blank nodes whose subtrees
    /// partition `x`'s subtree. A path secret destined for `x`'s subtree is encrypted once to each
    /// resolution node. Blank parents are skipped (descend into children); blank leaves contribute
    /// nothing; a populated parent contributes itself plus its unmerged leaves.
    pub fn resolution(&self, x: NodeIndex) -> Vec<NodeIndex> {
        match self.get(x) {
            Node::Blank => {
                if is_leaf(x) {
                    Vec::new()
                } else {
                    let n = self.num_leaves();
                    let mut r = self.resolution(left(x));
                    r.extend(self.resolution(right(x, n)));
                    r
                }
            }
            Node::Leaf(_) => vec![x],
            Node::Parent {
                unmerged_leaves, ..
            } => {
                let mut r = vec![x];
                r.extend(unmerged_leaves.iter().map(|&l| leaf_to_node(l)));
                r
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u32) -> LeafNode {
        LeafNode {
            cid: i as u64,
            kem_public: vec![i as u8],
            sig_public: vec![],
            leaf_index: i,
            signature: vec![],
        }
    }

    #[test]
    fn resolution_of_blank_internal_descends_to_leaves() {
        // n=4 full tree, all internal blank: resolution(root=3) = [0,2,4,6] (all leaves)
        let tree = RatchetTree::from_leaves((0..4).map(leaf).collect());
        assert_eq!(tree.resolution(3), vec![0, 2, 4, 6]);
        // sibling subtree of leaf 0's copath: node 5 (blank parent) -> [4,6]
        assert_eq!(tree.resolution(5), vec![4, 6]);
        // a populated leaf resolves to itself
        assert_eq!(tree.resolution(2), vec![2]);
    }

    #[test]
    fn resolution_skips_blank_leaf() {
        let mut tree = RatchetTree::from_leaves((0..2).map(leaf).collect());
        tree.set(2, Node::Blank); // blank out leaf 1
        assert_eq!(
            tree.resolution(1),
            vec![0],
            "blank leaf contributes nothing"
        );
    }
}
