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
    assert_eq!(left(3).unwrap(), 1);
    assert_eq!(right(3, 4).unwrap(), 5);
    assert_eq!(left(1).unwrap(), 0);
    assert_eq!(right(1, 4).unwrap(), 2);
    assert_eq!(left(5).unwrap(), 4);
    assert_eq!(right(5, 4).unwrap(), 6);
    for (x, p) in [(0, 1), (2, 1), (1, 3), (4, 5), (6, 5), (5, 3)] {
        assert_eq!(parent(x, 4).unwrap(), p, "parent({x}).unwrap()");
    }
    assert_eq!(sibling(0, 4).unwrap(), 2);
    assert_eq!(sibling(2, 4).unwrap(), 0);
    assert_eq!(sibling(1, 4).unwrap(), 5);
    assert_eq!(sibling(4, 4).unwrap(), 6);
    // leaf 0 (node 0): direct path 1->3, copath siblings 2,5
    assert_eq!(direct_path(0, 4).unwrap(), vec![1, 3]);
    assert_eq!(copath(0, 4).unwrap(), vec![2, 5]);
    // leaf 3 (node 6): direct path 5->3, copath siblings 4,1
    assert_eq!(direct_path(3, 4).unwrap(), vec![5, 3]);
    assert_eq!(copath(3, 4).unwrap(), vec![4, 1]);
}

#[test]
fn unbalanced_tree_n3() {
    //        3
    //       / \
    //      1   4(leaf2)
    //     / \
    //    0   2
    assert_eq!(
        right(3, 3).unwrap(),
        4,
        "right edge must descend to leaf node 4, not phantom 5"
    );
    assert_eq!(left(3).unwrap(), 1);
    assert_eq!(
        parent(4, 3).unwrap(),
        3,
        "right-edge leaf's parent is the root"
    );
    assert_eq!(parent(0, 3).unwrap(), 1);
    assert_eq!(parent(2, 3).unwrap(), 1);
    assert_eq!(parent(1, 3).unwrap(), 3);
    assert_eq!(
        sibling(4, 3).unwrap(),
        1,
        "leaf2's sibling is the left subtree node 1"
    );
    assert_eq!(sibling(1, 3).unwrap(), 4);
    assert_eq!(sibling(0, 3).unwrap(), 2);
    // leaf 2 (node 4): direct path is just the root
    assert_eq!(direct_path(2, 3).unwrap(), vec![3]);
    assert_eq!(copath(2, 3).unwrap(), vec![1]);
    // leaf 0 (node 0): 0 -> 1 -> 3
    assert_eq!(direct_path(0, 3).unwrap(), vec![1, 3]);
    assert_eq!(copath(0, 3).unwrap(), vec![2, 4]);
}

#[test]
fn single_leaf() {
    assert_eq!(root(1), 0);
    assert!(
        direct_path(0, 1).unwrap().is_empty(),
        "lone leaf is the root"
    );
    assert!(copath(0, 1).unwrap().is_empty());
}

#[test]
fn direct_path_and_copath_align_and_reach_root() {
    for n in 1..=16u32 {
        let r = root(n);
        for i in 0..n {
            let dp = direct_path(i, n).unwrap();
            let cp = copath(i, n).unwrap();
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
