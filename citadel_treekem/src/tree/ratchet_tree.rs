//! The ratchet tree array + the `resolution` operation (which drives path encryption).

use super::math::*;
use super::node::{LeafNode, Node};
use citadel_types::errors::Error;
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

    /// The leaf index occupied by `cid`, if a live (non-blank) leaf carries it.
    pub fn leaf_index_of_cid(&self, cid: u64) -> Option<LeafIndex> {
        (0..self.num_leaves()).find(|&i| match self.nodes.get(leaf_to_node(i) as usize) {
            Some(Node::Leaf(leaf)) => leaf.cid == cid,
            _ => false,
        })
    }

    /// The live leaf carrying `cid` (for sealing to that member's current KEM public key).
    pub fn leaf_of_cid(&self, cid: u64) -> Option<&LeafNode> {
        let idx = self.leaf_index_of_cid(cid)?;
        match self.nodes.get(leaf_to_node(idx) as usize) {
            Some(Node::Leaf(leaf)) => Some(leaf),
            _ => None,
        }
    }

    /// Borrow node `x`.
    pub fn get(&self, x: NodeIndex) -> Result<&Node, Error> {
        let len = self.nodes.len();
        self.nodes
            .get(x as usize)
            .ok_or_else(|| out_of_range(x, len))
    }

    /// Replace node `x`.
    pub fn set(&mut self, x: NodeIndex, node: Node) -> Result<(), Error> {
        let len = self.nodes.len();
        let slot = self
            .nodes
            .get_mut(x as usize)
            .ok_or_else(|| out_of_range(x, len))?;
        *slot = node;
        Ok(())
    }

    /// The **resolution** of node `x`: the ordered, minimal set of non-blank nodes whose subtrees
    /// partition `x`'s subtree. A path secret destined for `x`'s subtree is encrypted once to each
    /// resolution node. Blank parents are skipped (descend into children); blank leaves contribute
    /// nothing; a populated parent contributes itself plus its unmerged leaves.
    pub fn resolution(&self, x: NodeIndex) -> Result<Vec<NodeIndex>, Error> {
        let n = self.num_leaves();
        match self.get(x)? {
            Node::Blank => {
                if is_leaf(x) {
                    Ok(Vec::new())
                } else {
                    // Children sit one level lower, so the recursion ends within a tree's height.
                    let mut r = self.resolution(left(x)?)?;
                    r.extend(self.resolution(right(x, n)?)?);
                    Ok(r)
                }
            }
            Node::Leaf(_) => Ok(vec![x]),
            Node::Parent {
                unmerged_leaves, ..
            } => {
                let mut r = vec![x];
                for &l in unmerged_leaves {
                    check_leaf(l, n)?;
                    r.push(leaf_to_node(l));
                }
                Ok(r)
            }
        }
    }

    /// Insert a leaf, returning its index. Reuses the lowest blank leaf slot if any, else grows the tree
    /// by one leaf (preserving all existing node indices). The new leaf is added to the `unmerged_leaves`
    /// of every non-blank node on its direct path, since those nodes' keys do not yet cover it.
    pub fn add_leaf(&mut self, leaf: LeafNode) -> Result<LeafIndex, Error> {
        let n = self.num_leaves();
        let index = (0..n)
            .find(|&i| matches!(self.nodes.get(leaf_to_node(i) as usize), Some(Node::Blank)))
            .unwrap_or(n);
        self.add_leaf_at(index, leaf)?;
        Ok(index)
    }

    /// Insert a leaf at a specific (committer-assigned) index, growing the tree if needed. Processors use
    /// this so every member's tree agrees on leaf placement. The index must name a blank slot of the
    /// tree or the next new slot, and the tree may not grow past [`MAX_LEAVES`].
    pub fn add_leaf_at(&mut self, index: LeafIndex, mut leaf: LeafNode) -> Result<(), Error> {
        let n = self.num_leaves();
        if index > n || index >= MAX_LEAVES {
            return Err(citadel_io::error!(
                citadel_io::ErrorCode::CommitInvalid,
                format!("leaf {index} is neither a slot of the {n}-leaf tree nor the next one")
            ));
        }
        if index < n && !self.get(leaf_to_node(index))?.is_blank() {
            return Err(citadel_io::error!(
                citadel_io::ErrorCode::CommitInvalid,
                format!("leaf {index} is occupied")
            ));
        }
        let needed = node_width(index + 1) as usize;
        if self.nodes.len() < needed {
            self.nodes.resize(needed, Node::Blank);
        }
        leaf.leaf_index = index;
        self.set(leaf_to_node(index), Node::Leaf(leaf))?;

        let n2 = self.num_leaves();
        for node_x in direct_path(index, n2)? {
            if let Some(Node::Parent {
                unmerged_leaves, ..
            }) = self.nodes.get_mut(node_x as usize)
            {
                if !unmerged_leaves.contains(&index) {
                    unmerged_leaves.push(index);
                }
            }
        }
        Ok(())
    }

    /// Remove a leaf: blank the leaf and its entire direct path, so the removed member's keys are dead
    /// and the committer is forced to re-key the path next commit. The index must name an occupied leaf.
    pub fn remove_leaf(&mut self, index: LeafIndex) -> Result<(), Error> {
        let n = self.num_leaves();
        check_leaf(index, n)?;
        if !matches!(self.get(leaf_to_node(index))?, Node::Leaf(_)) {
            return Err(citadel_io::error!(
                citadel_io::ErrorCode::CommitInvalid,
                format!("leaf {index} is not occupied")
            ));
        }
        let path = direct_path(index, n)?;
        self.set(leaf_to_node(index), Node::Blank)?;
        for node_x in path {
            self.set(node_x, Node::Blank)?;
        }
        Ok(())
    }

    /// Checks the shape a received tree must have before any index into it is trusted: an odd node
    /// count of at most `node_width(MAX_LEAVES)`, leaves (or blanks) at even indices, parents (or
    /// blanks) at odd ones, and unmerged leaves that name leaves of the tree.
    pub fn validate(&self) -> Result<(), Error> {
        let len = self.nodes.len();
        if len.is_multiple_of(2) || len > node_width(MAX_LEAVES) as usize {
            return Err(citadel_io::error!(
                citadel_io::ErrorCode::TreeMalformed,
                format!("{len} nodes is not the width of a tree of 1..={MAX_LEAVES} leaves")
            ));
        }
        let n = self.num_leaves();
        for (x, node) in self.nodes.iter().enumerate() {
            let well_placed = match node {
                Node::Blank => true,
                Node::Leaf(_) => x.is_multiple_of(2),
                Node::Parent {
                    unmerged_leaves, ..
                } => !x.is_multiple_of(2) && unmerged_leaves.iter().all(|&l| l < n),
            };
            if !well_placed {
                return Err(citadel_io::error!(
                    citadel_io::ErrorCode::TreeMalformed,
                    format!("node {x} is misplaced or names a leaf outside the tree")
                ));
            }
        }
        Ok(())
    }
}

fn out_of_range(x: NodeIndex, len: usize) -> Error {
    citadel_io::error!(citadel_io::ErrorCode::TreeIndexOutOfRange, x, len)
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
        assert_eq!(tree.resolution(3).unwrap(), vec![0, 2, 4, 6]);
        // sibling subtree of leaf 0's copath: node 5 (blank parent) -> [4,6]
        assert_eq!(tree.resolution(5).unwrap(), vec![4, 6]);
        // a populated leaf resolves to itself
        assert_eq!(tree.resolution(2).unwrap(), vec![2]);
    }

    #[test]
    fn resolution_skips_blank_leaf() {
        let mut tree = RatchetTree::from_leaves((0..2).map(leaf).collect());
        tree.set(2, Node::Blank).unwrap(); // blank out leaf 1
        assert_eq!(
            tree.resolution(1).unwrap(),
            vec![0],
            "blank leaf contributes nothing"
        );
    }
}
