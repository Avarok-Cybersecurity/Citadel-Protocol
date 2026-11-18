//! Array-based left-balanced binary tree math (the MLS "tree math").
//!
//! A group of `n` leaves is stored as a flat array of `node_width(n) = 2n - 1` nodes: leaf `i` lives at
//! node index `2*i`, internal (parent) nodes at the odd indices. All structural relationships
//! (parent/child/sibling/direct-path/copath) are pure functions of the node index and the leaf count.
//!
//! These are the classic MLS formulas; the right-edge (`while p >= node_width` / `while r >= node_width`)
//! loops are what make them correct for **non-full** trees (`n` not a power of two), where the rightmost
//! subtree is shallower than the rest. Verified against hand-drawn trees in the unit tests.
//!
//! Indices reach this module from commits and welcomes, so every function that walks the tree first
//! checks that its input lies inside a tree of at most [`MAX_LEAVES`] leaves and returns an error
//! otherwise. Every loop is also bounded by `MAX_STEPS`, one step per bit of a node index.

use citadel_types::errors::Error;

/// A node index into the `2n-1` array (both leaves and parents).
pub type NodeIndex = u32;
/// A leaf index in `0..n` (member slot). Leaf `i` is at node index `2*i`.
pub type LeafIndex = u32;

/// The most leaves a ratchet tree may hold. Node indices then stay below `2^17`, so levels and
/// shifts stay far from the width of a `u32`, and a tree's memory stays bounded.
pub const MAX_LEAVES: u32 = 1 << 16;

/// The most steps any walk in this module takes: one per bit of a node index.
const MAX_STEPS: u32 = NodeIndex::BITS;

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

/// Checks that `n` is a permitted leaf count and `x` a node of that tree; returns the tree's width.
pub fn check_node(x: NodeIndex, n: u32) -> Result<u32, Error> {
    if n == 0 || n > MAX_LEAVES {
        return Err(citadel_io::error!(
            citadel_io::ErrorCode::TreeMalformed,
            format!("a tree of {n} leaves is outside 1..={MAX_LEAVES}")
        ));
    }
    let w = node_width(n);
    if x >= w {
        return Err(citadel_io::error!(
            citadel_io::ErrorCode::TreeIndexOutOfRange,
            x,
            w
        ));
    }
    Ok(w)
}

/// Checks that leaf `i` is a leaf of a tree of `n` leaves.
pub fn check_leaf(i: LeafIndex, n: u32) -> Result<(), Error> {
    if i >= n {
        return Err(citadel_io::error!(
            citadel_io::ErrorCode::TreeIndexOutOfRange,
            format!("leaf {i}"),
            n
        ));
    }
    check_node(leaf_to_node(i), n).map(|_| ())
}

fn no_children(x: NodeIndex) -> Error {
    citadel_io::error!(
        citadel_io::ErrorCode::TreeMalformed,
        format!("node {x} is a leaf and has no children")
    )
}

fn walk_exceeded(x: NodeIndex) -> Error {
    citadel_io::error!(
        citadel_io::ErrorCode::TreeMalformed,
        format!("the walk from node {x} did not end within {MAX_STEPS} steps")
    )
}

/// Left child of parent `x`.
pub fn left(x: NodeIndex) -> Result<NodeIndex, Error> {
    let k = level(x);
    if k == 0 || k >= MAX_STEPS {
        return Err(no_children(x));
    }
    Ok(x ^ (1 << (k - 1)))
}

/// Right child of parent `x` in a tree of `n` leaves. The naive right child can fall off the
/// (shallower) right edge, so descend left until it lands inside the tree.
pub fn right(x: NodeIndex, n: u32) -> Result<NodeIndex, Error> {
    let w = check_node(x, n)?;
    let k = level(x);
    if k == 0 {
        return Err(no_children(x));
    }
    let mut r = x ^ (3 << (k - 1));
    for _ in 0..MAX_STEPS {
        if r < w {
            return Ok(r);
        }
        r = left(r)?;
    }
    Err(walk_exceeded(x))
}

/// One step toward the root in the *implied full* tree (may overshoot a non-full tree's width).
/// `None` once the step would leave the range of a node index.
fn parent_step(x: NodeIndex) -> Option<NodeIndex> {
    let k = level(x);
    let bit = 1u32.checked_shl(k)?;
    let b = x.checked_shr(k + 1)? & 1;
    Some((x | bit) ^ (b << (k + 1)))
}

/// Parent of `x` in a tree of `n` leaves. Repeats `parent_step` while it overshoots the width, which
/// is what pulls a right-edge node up to its true (shallower) parent.
pub fn parent(x: NodeIndex, n: u32) -> Result<NodeIndex, Error> {
    let w = check_node(x, n)?;
    if x == root(n) {
        return Err(citadel_io::error!(
            citadel_io::ErrorCode::TreeMalformed,
            format!("the root {x} has no parent")
        ));
    }
    let mut p = x;
    for _ in 0..MAX_STEPS {
        p = parent_step(p).ok_or_else(|| walk_exceeded(x))?;
        if p < w {
            return Ok(p);
        }
    }
    Err(walk_exceeded(x))
}

/// Sibling of `x` in a tree of `n` leaves.
pub fn sibling(x: NodeIndex, n: u32) -> Result<NodeIndex, Error> {
    let p = parent(x, n)?;
    if x < p {
        right(p, n)
    } else {
        left(p)
    }
}

/// The direct path of leaf `i`: the parents from `leaf`'s parent up to and including the root.
/// Empty for a single-leaf group (the leaf is the root).
pub fn direct_path(i: LeafIndex, n: u32) -> Result<Vec<NodeIndex>, Error> {
    check_leaf(i, n)?;
    let r = root(n);
    let mut x = leaf_to_node(i);
    let mut path = Vec::new();
    for _ in 0..MAX_STEPS {
        if x == r {
            return Ok(path);
        }
        x = parent(x, n)?;
        path.push(x);
    }
    Err(walk_exceeded(leaf_to_node(i)))
}

/// The copath of leaf `i`: the sibling at each step from the leaf up to (excluding) the root. Same
/// length as [`direct_path`], aligned element-wise (copath[k] is the sibling of the node *below*
/// direct_path[k], i.e. the subtree that direct_path[k] must encrypt its new secret to).
pub fn copath(i: LeafIndex, n: u32) -> Result<Vec<NodeIndex>, Error> {
    check_leaf(i, n)?;
    let r = root(n);
    let mut x = leaf_to_node(i);
    let mut path = Vec::new();
    for _ in 0..MAX_STEPS {
        if x == r {
            return Ok(path);
        }
        path.push(sibling(x, n)?);
        x = parent(x, n)?;
    }
    Err(walk_exceeded(leaf_to_node(i)))
}

#[cfg(test)]
#[path = "math_tests.rs"]
mod tests;
