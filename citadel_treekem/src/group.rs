//! Per-member CGKA state machine: `commit_update` (re-key my path → new epoch) and `process_commit`
//! (apply someone else's re-key → same new epoch). Add/Remove/Welcome land in the next milestone; this
//! milestone establishes the core invariant: **after a commit, every member derives the same epoch
//! secret**, with forward secrecy and post-compromise security across epochs.

use crate::crypto::Secret;
use crate::path::{apply_update_path, generate_update_path, UpdatePath};
use crate::schedule::EpochSecrets;
use crate::tree::math::{leaf_to_node, LeafIndex, NodeIndex};
use crate::tree::ratchet_tree::RatchetTree;
use citadel_types::errors::Error;
use std::collections::HashMap;

/// One member's view of the group.
#[derive(Clone)]
pub struct GroupState {
    /// The (public) ratchet tree.
    pub tree: RatchetTree,
    /// This member's leaf index.
    pub own_leaf: LeafIndex,
    /// Path secrets this member holds: its leaf node + the nodes on its own direct path it has learned.
    own_secrets: HashMap<NodeIndex, Secret>,
    /// The current epoch counter.
    pub epoch: u64,
    /// The current epoch's derived secrets.
    secrets: EpochSecrets,
    /// Confirmed transcript hash (chains commits; binds the epoch secret to the exact history).
    transcript_hash: [u8; 32],
}

impl GroupState {
    /// Construct a member's state directly from a shared public tree, its own leaf secret, and a shared
    /// genesis root secret. (The Add/Welcome bootstrap that produces this in the real protocol is the
    /// next milestone; this constructor lets the CGKA core be exercised end-to-end now.)
    pub fn bootstrap(
        tree: RatchetTree,
        own_leaf: LeafIndex,
        own_leaf_secret: Secret,
        genesis_root_secret: &Secret,
    ) -> Self {
        let transcript_hash = [0u8; 32];
        let secrets = EpochSecrets::genesis(genesis_root_secret, &transcript_hash);
        let mut own_secrets = HashMap::new();
        own_secrets.insert(leaf_to_node(own_leaf), own_leaf_secret);
        Self {
            tree,
            own_leaf,
            own_secrets,
            epoch: 0,
            secrets,
            transcript_hash,
        }
    }

    /// The per-epoch application encryption secret (feeds the message ratchet — wired in M3).
    pub fn encryption_secret(&self) -> &Secret {
        &self.secrets.encryption_secret
    }

    /// Re-key this member's direct path with a fresh leaf secret, advancing to a new epoch. Returns the
    /// `UpdatePath` to broadcast so other members can `process_commit` into the same epoch.
    pub fn commit_update(&mut self, fresh_leaf_secret: Secret) -> Result<UpdatePath, Error> {
        let (update, root_secret, own_secrets) =
            generate_update_path(&mut self.tree, self.own_leaf, fresh_leaf_secret)?;
        self.own_secrets = own_secrets;
        self.advance_epoch(&root_secret, &update);
        Ok(update)
    }

    /// Apply another member's `UpdatePath`, advancing into the same new epoch.
    pub fn process_commit(&mut self, update: &UpdatePath) -> Result<(), Error> {
        let (root_secret, learned) = apply_update_path(&mut self.tree, update, &self.own_secrets)?;
        for (node, secret) in learned {
            self.own_secrets.insert(node, secret);
        }
        self.advance_epoch(&root_secret, update);
        Ok(())
    }

    /// Roll the transcript + key schedule forward into the next epoch from a new root secret.
    fn advance_epoch(&mut self, root_secret: &Secret, update: &UpdatePath) {
        self.transcript_hash = next_transcript(&self.transcript_hash, update);
        let prev_init = self.secrets.init_secret;
        self.secrets = EpochSecrets::derive(root_secret, &prev_init, &self.transcript_hash);
        self.epoch += 1;
    }
}

/// Chain the transcript hash over an applied commit so every member's epoch secret is bound to the exact
/// same commit history (a divergent commit yields a divergent epoch secret).
fn next_transcript(prev: &[u8; 32], update: &UpdatePath) -> [u8; 32] {
    let serialized = bincode::serialize(update).unwrap_or_default();
    let mut hasher = blake3::Hasher::new_derive_key("citadel-treekem-transcript-v1");
    hasher.update(prev);
    hasher.update(&serialized);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::node_keypair_from_path_secret;
    use crate::tree::node::LeafNode;

    /// Build `n` members sharing one public tree, each holding its own leaf secret, all starting from the
    /// same genesis epoch. Returns the per-member `GroupState`s.
    fn make_group(n: u32) -> Vec<GroupState> {
        let genesis_root = [42u8; 32];
        // Per-member leaf secrets (distinct), and their derived public leaf keys.
        let leaf_secrets: Vec<Secret> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
        let leaves: Vec<LeafNode> = leaf_secrets
            .iter()
            .enumerate()
            .map(|(i, ps)| {
                let (pk, _sk) = node_keypair_from_path_secret(ps).unwrap();
                LeafNode {
                    cid: i as u64 + 100,
                    kem_public: pk,
                    sig_public: vec![],
                    leaf_index: i as u32,
                    signature: vec![],
                }
            })
            .collect();
        let tree = RatchetTree::from_leaves(leaves);
        (0..n)
            .map(|i| {
                GroupState::bootstrap(tree.clone(), i, leaf_secrets[i as usize], &genesis_root)
            })
            .collect()
    }

    #[test]
    fn all_members_derive_same_epoch_secret_after_commit() {
        for n in [2u32, 3, 4, 5, 7, 8] {
            let mut members = make_group(n);
            // Member 0 commits a fresh path update.
            let update = members[0].commit_update([0xAB; 32]).unwrap();
            // Everyone else processes it.
            for m in members.iter_mut().skip(1) {
                m.process_commit(&update).unwrap();
            }
            // All members must now agree on the epoch + the encryption secret.
            let secret0 = *members[0].encryption_secret();
            for (i, m) in members.iter().enumerate() {
                assert_eq!(m.epoch, 1, "n={n} member {i}: epoch");
                assert_eq!(
                    m.encryption_secret(),
                    &secret0,
                    "n={n} member {i}: epoch secret must match the committer",
                );
            }
        }
    }

    #[test]
    fn forward_secrecy_and_pcs_across_two_commits() {
        let mut members = make_group(4);
        let u1 = members[0].commit_update([1u8; 32]).unwrap();
        for m in members.iter_mut().skip(1) {
            m.process_commit(&u1).unwrap();
        }
        let epoch1 = *members[0].encryption_secret();

        // A different member commits again with a fresh secret.
        let u2 = members[2].commit_update([2u8; 32]).unwrap();
        members[0].process_commit(&u2).unwrap();
        members[1].process_commit(&u2).unwrap();
        members[3].process_commit(&u2).unwrap();
        let epoch2 = *members[0].encryption_secret();

        assert_ne!(
            epoch1, epoch2,
            "consecutive epochs must have distinct secrets (FS)"
        );
        for m in &members {
            assert_eq!(m.epoch, 2);
            assert_eq!(m.encryption_secret(), &epoch2, "all agree on epoch 2");
        }
    }

    #[test]
    fn removed_subtree_key_cannot_decrypt() {
        // Sanity: a member who is NOT in the resolution targeted by a ciphertext can't open it. Member 0
        // commits; member 1 processing must succeed, but feeding member 1's update to a fresh outsider
        // state with a different leaf secret must fail to find a decryptable node.
        let mut members = make_group(4);
        let update = members[0].commit_update([7u8; 32]).unwrap();
        // An outsider with an unrelated leaf secret at a bogus leaf can't process.
        let tree = members[0].tree.clone();
        // Replace leaf 1 with an unknown key so the "outsider" holds no matching secret.
        let mut outsider = GroupState::bootstrap(tree, 1, [0x99; 32], &[42u8; 32]);
        // outsider's stored secret for its leaf doesn't match the tree's leaf-1 public key -> no node
        // in the targeted resolution is openable with it.
        assert!(
            outsider.process_commit(&update).is_err(),
            "a member whose secret doesn't match its tree leaf cannot recover the path secret",
        );
    }
}
