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

    /// Insert a leaf, returning its index. Reuses the lowest blank leaf slot if any, else grows the tree
    /// by one leaf (preserving all existing node indices). The new leaf is added to the `unmerged_leaves`
    /// of every non-blank node on its direct path, since those nodes' keys do not yet cover it.
    pub fn add_leaf(&mut self, leaf: LeafNode) -> LeafIndex {
        let n = self.num_leaves();
        let index = (0..n)
            .find(|&i| self.get(leaf_to_node(i)).is_blank())
            .unwrap_or(n);
        self.add_leaf_at(index, leaf);
        index
    }

    /// Insert a leaf at a specific (committer-assigned) index, growing the tree if needed. Processors use
    /// this so every member's tree agrees on leaf placement.
    pub fn add_leaf_at(&mut self, index: LeafIndex, mut leaf: LeafNode) {
        let needed = node_width(index + 1) as usize;
        if self.nodes.len() < needed {
            self.nodes.resize(needed, Node::Blank);
        }
        leaf.leaf_index = index;
        self.set(leaf_to_node(index), Node::Leaf(leaf));

        let n2 = self.num_leaves();
        for node_x in direct_path(index, n2) {
            if let Node::Parent {
                unmerged_leaves, ..
            } = &mut self.nodes[node_x as usize]
            {
                if !unmerged_leaves.contains(&index) {
                    unmerged_leaves.push(index);
                }
            }
        }
    }

    /// Remove a leaf: blank the leaf and its entire direct path, so the removed member's keys are dead
    /// and the committer is forced to re-key the path next commit.
    pub fn remove_leaf(&mut self, index: LeafIndex) {
        let n = self.num_leaves();
        self.set(leaf_to_node(index), Node::Blank);
        for node_x in direct_path(index, n) {
            self.set(node_x, Node::Blank);
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
