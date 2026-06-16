//! Array-based left-balanced binary tree math (the MLS "tree math").
//!
//! A group of `n` leaves is stored as a flat array of `node_width(n) = 2n - 1` nodes: leaf `i` lives at
//! node index `2*i`, internal (parent) nodes at the odd indices. All structural relationships
//! (parent/child/sibling/direct-path/copath) are pure functions of the node index and the leaf count.
//!
//! These are the classic MLS formulas; the right-edge (`while p >= node_width` / `while r >= node_width`)
//! loops are what make them correct for **non-full** trees (`n` not a power of two), where the rightmost
//! subtree is shallower than the rest. Verified against hand-drawn trees in the unit tests below.

/// A node index into the `2n-1` array (both leaves and parents).
pub type NodeIndex = u32;
/// A leaf index in `0..n` (member slot). Leaf `i` is at node index `2*i`.
pub type LeafIndex = u32;

/// `floor(log2(x))`; `0` for `x == 0`.
fn log2(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    31 - x.leading_zeros()
}

/// The level of a node: `0` for leaves (even indices), else the number of trailing one-bits.
pub fn level(x: NodeIndex) -> u32 {
    if x & 1 == 0 {
        return 0;
    }
    x.trailing_ones()
}

/// Total node count for `n` leaves (`2n - 1`, or `0` for the empty tree).
pub fn node_width(n: u32) -> u32 {
    if n == 0 {
        0
    } else {
        2 * (n - 1) + 1
    }
}

/// The root node index for `n` leaves.
pub fn root(n: u32) -> NodeIndex {
    let w = node_width(n);
    (1 << log2(w)) - 1
}

/// The node index of leaf `i`.
pub fn leaf_to_node(i: LeafIndex) -> NodeIndex {
    i * 2
}

/// Whether `x` is a leaf node.
pub fn is_leaf(x: NodeIndex) -> bool {
    x & 1 == 0
}

/// Left child of parent `x`. Always in range for a valid parent node.
pub fn left(x: NodeIndex) -> NodeIndex {
    let k = level(x);
    debug_assert!(k != 0, "leaf has no children");
    x ^ (1 << (k - 1))
}

/// Right child of parent `x` in a tree of `n` leaves. The naive right child can fall off the
/// (shallower) right edge, so descend left until it lands inside the tree.
pub fn right(x: NodeIndex, n: u32) -> NodeIndex {
    let k = level(x);
    debug_assert!(k != 0, "leaf has no children");
    let mut r = x ^ (3 << (k - 1));
    let w = node_width(n);
    while r >= w {
        r = left(r);
    }
    r
}

/// One step toward the root in the *implied full* tree (may overshoot a non-full tree's width).
fn parent_step(x: NodeIndex) -> NodeIndex {
    let k = level(x);
    let b = (x >> (k + 1)) & 1;
    (x | (1 << k)) ^ (b << (k + 1))
}

/// Parent of `x` in a tree of `n` leaves. Repeats `parent_step` while it overshoots the width, which
/// is what pulls a right-edge node up to its true (shallower) parent.
pub fn parent(x: NodeIndex, n: u32) -> NodeIndex {
    debug_assert!(x != root(n), "root has no parent");
    let w = node_width(n);
    let mut p = parent_step(x);
    while p >= w {
        p = parent_step(p);
    }
    p
}

/// Sibling of `x` in a tree of `n` leaves.
pub fn sibling(x: NodeIndex, n: u32) -> NodeIndex {
    let p = parent(x, n);
    if x < p {
        right(p, n)
    } else {
        left(p)
    }
}

/// The direct path of leaf `i`: the parents from `leaf`'s parent up to and including the root.
/// Empty for a single-leaf group (the leaf is the root).
pub fn direct_path(i: LeafIndex, n: u32) -> Vec<NodeIndex> {
    let r = root(n);
    let mut x = leaf_to_node(i);
    let mut path = Vec::new();
    if x == r {
        return path;
    }
    loop {
        x = parent(x, n);
        path.push(x);
        if x == r {
            break;
        }
    }
    path
}

/// The copath of leaf `i`: the sibling at each step from the leaf up to (excluding) the root. Same
/// length as [`direct_path`], aligned element-wise (copath[k] is the sibling of the node *below*
/// direct_path[k], i.e. the subtree that direct_path[k] must encrypt its new secret to).
pub fn copath(i: LeafIndex, n: u32) -> Vec<NodeIndex> {
    let r = root(n);
    let mut x = leaf_to_node(i);
    let mut path = Vec::new();
    while x != r {
        path.push(sibling(x, n));
        x = parent(x, n);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_and_roots() {
        assert_eq!(node_width(0), 0);
        assert_eq!(node_width(1), 1);
        assert_eq!(node_width(3), 5);
        assert_eq!(node_width(4), 7);
        assert_eq!(root(1), 0);
        assert_eq!(root(2), 1);
        assert_eq!(root(3), 3);
        assert_eq!(root(4), 3);
        assert_eq!(root(5), 7);
    }

    #[test]
    fn levels() {
        // 0..=6 levels for the n=4 full tree
        let lv: Vec<u32> = (0..7).map(level).collect();
        assert_eq!(lv, vec![0, 1, 0, 2, 0, 1, 0]);
    }

    #[test]
    fn full_tree_n4() {
        // node 3 root; children 1 and 5; grandchildren 0,2 and 4,6
        assert_eq!(left(3), 1);
        assert_eq!(right(3, 4), 5);
        assert_eq!(left(1), 0);
        assert_eq!(right(1, 4), 2);
        assert_eq!(left(5), 4);
        assert_eq!(right(5, 4), 6);
        for (x, p) in [(0, 1), (2, 1), (1, 3), (4, 5), (6, 5), (5, 3)] {
            assert_eq!(parent(x, 4), p, "parent({x})");
        }
        assert_eq!(sibling(0, 4), 2);
        assert_eq!(sibling(2, 4), 0);
        assert_eq!(sibling(1, 4), 5);
        assert_eq!(sibling(4, 4), 6);
        // leaf 0 (node 0): direct path 1->3, copath siblings 2,5
        assert_eq!(direct_path(0, 4), vec![1, 3]);
        assert_eq!(copath(0, 4), vec![2, 5]);
        // leaf 3 (node 6): direct path 5->3, copath siblings 4,1
        assert_eq!(direct_path(3, 4), vec![5, 3]);
        assert_eq!(copath(3, 4), vec![4, 1]);
    }

    #[test]
    fn unbalanced_tree_n3() {
        //        3
        //       / \
        //      1   4(leaf2)
        //     / \
        //    0   2
        assert_eq!(
            right(3, 3),
            4,
            "right edge must descend to leaf node 4, not phantom 5"
        );
        assert_eq!(left(3), 1);
        assert_eq!(parent(4, 3), 3, "right-edge leaf's parent is the root");
        assert_eq!(parent(0, 3), 1);
        assert_eq!(parent(2, 3), 1);
        assert_eq!(parent(1, 3), 3);
        assert_eq!(
            sibling(4, 3),
            1,
            "leaf2's sibling is the left subtree node 1"
        );
        assert_eq!(sibling(1, 3), 4);
        assert_eq!(sibling(0, 3), 2);
        // leaf 2 (node 4): direct path is just the root
        assert_eq!(direct_path(2, 3), vec![3]);
        assert_eq!(copath(2, 3), vec![1]);
        // leaf 0 (node 0): 0 -> 1 -> 3
        assert_eq!(direct_path(0, 3), vec![1, 3]);
        assert_eq!(copath(0, 3), vec![2, 4]);
    }

    #[test]
    fn single_leaf() {
        assert_eq!(root(1), 0);
        assert!(direct_path(0, 1).is_empty(), "lone leaf is the root");
        assert!(copath(0, 1).is_empty());
    }

    #[test]
    fn direct_path_and_copath_align_and_reach_root() {
        for n in 1..=16u32 {
            let r = root(n);
            for i in 0..n {
                let dp = direct_path(i, n);
                let cp = copath(i, n);
                assert_eq!(dp.len(), cp.len(), "n={n} leaf={i}: dp/cp length mismatch");
                if !dp.is_empty() {
                    assert_eq!(
                        *dp.last().unwrap(),
                        r,
                        "n={n} leaf={i}: dp must end at root"
                    );
                }
                // every copath sibling is a real node, and disjoint from the direct path
                let w = node_width(n);
                for (&d, &c) in dp.iter().zip(cp.iter()) {
                    assert!(d < w && c < w, "n={n} leaf={i}: index out of range");
                    assert_ne!(d, c);
                }
            }
        }
    }
}
