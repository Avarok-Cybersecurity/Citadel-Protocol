//! Update-path generation (committer) and application (everyone else) — the heart of the ratchet.
//!
//! A committer re-keys its own leaf→root **direct path**: it picks a fresh leaf secret, derives a chain
//! of path secrets up to the root, and for each direct-path node encrypts that node's path secret to the
//! **resolution of the copath sibling** (the rest of the group on that side). Each other member can open
//! exactly one of those ciphertexts — for the node where its own subtree meets the committer's path — and
//! then KDF-ratchets the recovered secret up to the same root secret.

use crate::crypto::{self, Secret, SecretMap};
use crate::signing::{leaf_signature_keys, LeafSigningKey};
use crate::tree::math::*;
use crate::tree::node::Node;
use crate::tree::ratchet_tree::RatchetTree;
use citadel_types::errors::Error;
use serde::{Deserialize, Serialize};

/// An ML-KEM-sealed path secret (KEM ciphertext + AEAD ciphertext).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeCiphertext {
    pub kem_ct: Vec<u8>,
    pub aead_ct: Vec<u8>,
}

/// One node on the committer's direct path: its fresh KEM public key, and the path secret sealed to
/// each node in the resolution of the corresponding copath sibling (same order as `resolution`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePathNode {
    pub kem_public: Vec<u8>,
    pub encrypted_path_secrets: Vec<HpkeCiphertext>,
}

/// A full re-key of a member's direct path, broadcast to the group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePath {
    /// The committer's leaf index.
    pub leaf_index: u32,
    /// The committer's fresh leaf KEM public key.
    pub leaf_kem_public: Vec<u8>,
    /// The committer's fresh leaf signature verifying key, derived from the same fresh leaf
    /// secret: a commit replaces both, so a copy of the committer's previous leaf can neither
    /// open nor sign anything at the new epoch.
    pub leaf_sig_public: Vec<u8>,
    /// One entry per node on the committer's direct path (leaf's parent → root).
    pub nodes: Vec<UpdatePathNode>,
}

/// Committer re-keys leaf `leaf_index`'s direct path with a fresh `leaf_secret`, deriving its leaf
/// and direct-path keys. Mutates `tree` to the post-commit public state and returns
/// `(update_path, root_secret, own_path_secrets, leaf_signing_key)`.
pub fn generate_update_path(
    tree: &mut RatchetTree,
    leaf_index: LeafIndex,
    leaf_secret: Secret,
) -> Result<(UpdatePath, Secret, SecretMap, LeafSigningKey), Error> {
    let n = tree.num_leaves();
    let dp = direct_path(leaf_index, n)?;
    let cp = copath(leaf_index, n)?;
    let leaf_node_idx = leaf_to_node(leaf_index);

    // Our retained secrets: leaf (uses leaf_secret) + each direct-path node (chained).
    let mut own_secrets = SecretMap::default();
    own_secrets.insert(leaf_node_idx, leaf_secret);

    // Fresh leaf keypair → update our leaf node's public key.
    let (leaf_pk, _leaf_sk) = crypto::node_keypair_from_path_secret(&leaf_secret)?;
    let (leaf_sig_public, leaf_signing_key) = leaf_signature_keys(&leaf_secret);
    if let Node::Leaf(mut l) = tree.get(leaf_node_idx)?.clone() {
        l.kem_public = leaf_pk.clone();
        l.sig_public = leaf_sig_public.clone();
        tree.set(leaf_node_idx, Node::Leaf(l))?;
    } else {
        return Err(Error::generic("treekem: committer leaf slot is not a leaf"));
    }

    // Path secrets up the direct path (path_secrets[i] is for dp[i]).
    let mut path_secrets: Vec<Secret> = Vec::with_capacity(dp.len());
    let mut cur = leaf_secret;
    for _ in &dp {
        cur = crypto::derive_path_secret(&cur);
        path_secrets.push(cur);
    }
    // Single-member group: the leaf is the root; root secret is one ratchet step off the leaf secret.
    let root_secret = path_secrets
        .last()
        .copied()
        .unwrap_or_else(|| crypto::derive_path_secret(&leaf_secret));

    // For each direct-path node: new keypair, update tree, seal its path secret to the copath resolution.
    let mut update_nodes = Vec::with_capacity(dp.len());
    for ((&node_x, &ps), &cp_node) in dp.iter().zip(path_secrets.iter()).zip(cp.iter()) {
        own_secrets.insert(node_x, ps);
        let (node_pk, _node_sk) = crypto::node_keypair_from_path_secret(&ps)?;
        tree.set(
            node_x,
            Node::Parent {
                kem_public: node_pk.clone(),
                parent_hash: [0u8; 32],
                unmerged_leaves: Vec::new(),
            },
        )?;
        // The copath sibling is disjoint from the direct path, so its resolution is unaffected by our edits.
        let recipients = tree.resolution(cp_node)?;
        let mut encrypted = Vec::with_capacity(recipients.len());
        for r in recipients {
            let pk = tree
                .get(r)?
                .kem_public()
                .ok_or_else(|| Error::generic("treekem: resolution node has no KEM public key"))?;
            let (kem_ct, aead_ct) = crypto::hpke_seal(pk, &ps)?;
            encrypted.push(HpkeCiphertext { kem_ct, aead_ct });
        }
        update_nodes.push(UpdatePathNode {
            kem_public: node_pk,
            encrypted_path_secrets: encrypted,
        });
    }

    let update = UpdatePath {
        leaf_index,
        leaf_kem_public: leaf_pk,
        leaf_sig_public,
        nodes: update_nodes,
    };
    Ok((update, root_secret, own_secrets, leaf_signing_key))
}

/// A member applies a committer's `UpdatePath`. Mutates `tree` to the post-commit public state and
/// returns `(root_secret, newly_learned_secrets)` for the committer's direct-path nodes from the point
/// where it intersects this member's subtree, up to the root.
pub fn apply_update_path(
    tree: &mut RatchetTree,
    update: &UpdatePath,
    own_secrets: &SecretMap,
) -> Result<(Secret, SecretMap), Error> {
    let n = tree.num_leaves();
    let committer = update.leaf_index;
    let dp = direct_path(committer, n)?;
    let cp = copath(committer, n)?;
    if dp.len() != update.nodes.len() {
        return Err(Error::generic("treekem: update path length mismatch"));
    }

    // 1. Install the committer's new leaf + direct-path public keys, each of the tree's suite.
    crypto::suite_of(&update.leaf_kem_public)?;
    for node in &update.nodes {
        crypto::suite_of(&node.kem_public)?;
    }
    if let Node::Leaf(mut l) = tree.get(leaf_to_node(committer))?.clone() {
        l.kem_public = update.leaf_kem_public.clone();
        l.sig_public = update.leaf_sig_public.clone();
        tree.set(leaf_to_node(committer), Node::Leaf(l))?;
    } else {
        return Err(Error::generic("treekem: committer leaf slot is not a leaf"));
    }
    for (&node_x, node) in dp.iter().zip(update.nodes.iter()) {
        tree.set(
            node_x,
            Node::Parent {
                kem_public: node.kem_public.clone(),
                parent_hash: [0u8; 32],
                unmerged_leaves: Vec::new(),
            },
        )?;
    }

    // 2. Find the lowest copath node whose resolution contains a node we hold a secret for, and open it.
    for (d, &cp_node) in cp.iter().enumerate() {
        let recipients = tree.resolution(cp_node)?;
        for (ri, &r) in recipients.iter().enumerate() {
            let Some(ps_known) = own_secrets.get(&r) else {
                continue;
            };
            let hpke = update
                .nodes
                .get(d)
                .and_then(|node| node.encrypted_path_secrets.get(ri))
                .ok_or_else(|| Error::generic("treekem: missing ciphertext for resolution node"))?;
            let ps_bytes =
                crypto::hpke_open_with_path_secret(ps_known, &hpke.kem_ct, &hpke.aead_ct)?;
            if ps_bytes.len() != crypto::SECRET_LEN {
                return Err(Error::generic(
                    "treekem: decrypted path secret has wrong length",
                ));
            }
            let mut ps: Secret = [0u8; crypto::SECRET_LEN];
            ps.copy_from_slice(&ps_bytes);

            // 3. Ratchet the recovered secret from dp[d] up to the root.
            let mut learned = SecretMap::default();
            // dp and cp have the same length, so dp[d] exists; ratchet from it up to the root.
            let mut cur = ps;
            let mut path_above = dp.iter().skip(d);
            if let Some(&opened) = path_above.next() {
                learned.insert(opened, cur);
            }
            for &node_x in path_above {
                cur = crypto::derive_path_secret(&cur);
                learned.insert(node_x, cur);
            }
            return Ok((cur, learned));
        }
    }

    Err(Error::generic(
        "treekem: no decryptable node found for this member in the update path",
    ))
}
