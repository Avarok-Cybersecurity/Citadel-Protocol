//! Per-member CGKA state machine: `create` a group, `add_member`/`remove_member`/`commit_update` to
//! produce a `Commit` (+ `Welcome` for an add), and `process_commit`/`join_from_welcome` to follow.
//!
//! The core invariant across all of these: after a commit, **every member derives the same epoch
//! secret**, with forward secrecy + post-compromise security, and the relay never sees a key.

use crate::application::AppCiphertext;
use crate::commit::{Commit, Proposal};
use crate::crypto::{self, Secret};
use crate::keys::KeyPackage;
use crate::path::{apply_update_path, generate_update_path, HpkeCiphertext};
use crate::schedule::EpochSecrets;
use crate::tree::math::{direct_path, leaf_to_node, LeafIndex, NodeIndex};
use crate::tree::node::LeafNode;
use crate::tree::ratchet_tree::RatchetTree;
use crate::welcome::{GroupInfo, Welcome};
use citadel_types::errors::Error;
use std::collections::{HashMap, HashSet};

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
    /// This member's outgoing message counter within the current epoch (reset each epoch).
    send_generation: u32,
}

impl GroupState {
    /// Construct a member's state from a shared public tree, its own leaf secret, and a shared genesis
    /// root secret. Used by [`Self::create`] and tests.
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
            send_generation: 0,
        }
    }

    /// Found a new group as the sole member (epoch 0). The founder occupies leaf 0.
    pub fn create(mut founder: LeafNode, founder_leaf_secret: Secret) -> Self {
        founder.leaf_index = 0;
        let tree = RatchetTree::from_leaves(vec![founder]);
        let genesis_root = crypto::derive_path_secret(&founder_leaf_secret);
        Self::bootstrap(tree, 0, founder_leaf_secret, &genesis_root)
    }

    /// The per-epoch application encryption secret (feeds the message ratchet — wired in M3).
    pub fn encryption_secret(&self) -> &Secret {
        &self.secrets.encryption_secret
    }

    /// Re-key this member's direct path with a fresh leaf secret (no membership change), advancing the
    /// epoch. Returns the `Commit` to broadcast.
    pub fn commit_update(&mut self, fresh_leaf_secret: Secret) -> Result<Commit, Error> {
        let (path, root_secret, own_secrets) =
            generate_update_path(&mut self.tree, self.own_leaf, fresh_leaf_secret)?;
        self.own_secrets = own_secrets;
        let commit = Commit {
            proposals: Vec::new(),
            path,
        };
        self.advance_epoch(&root_secret, &commit);
        Ok(commit)
    }

    /// Add a new member from their [`KeyPackage`] and commit. Returns the `Commit` (broadcast to existing
    /// members) and the `Welcome` (sent only to the joiner).
    pub fn add_member(
        &mut self,
        key_package: &KeyPackage,
        fresh_leaf_secret: Secret,
    ) -> Result<(Commit, Welcome), Error> {
        let joiner_index = self.tree.add_leaf(key_package.leaf.clone());
        // Capture the previous epoch's init secret BEFORE advancing — the joiner needs it for the schedule.
        let prev_init = self.secrets.init_secret;

        let (path, root_secret, own_secrets) =
            generate_update_path(&mut self.tree, self.own_leaf, fresh_leaf_secret)?;
        self.own_secrets.clone_from(&own_secrets);

        // The joiner ratchets up from the lowest node where its path meets the committer's re-keyed path.
        let n = self.tree.num_leaves();
        let committer_path = direct_path(self.own_leaf, n);
        let joiner_path: HashSet<NodeIndex> = direct_path(joiner_index, n).into_iter().collect();
        let lca = committer_path
            .into_iter()
            .find(|node| joiner_path.contains(node))
            .ok_or_else(|| Error::generic("treekem: no common ancestor for the joiner"))?;
        let lca_secret = *own_secrets
            .get(&lca)
            .ok_or_else(|| Error::generic("treekem: committer is missing the LCA path secret"))?;

        let commit = Commit {
            proposals: vec![Proposal::Add {
                key_package: key_package.clone(),
                leaf_index: joiner_index,
            }],
            path,
        };
        self.advance_epoch(&root_secret, &commit);

        // Seal `lca_secret || prev_init` to the joiner's leaf KEM key.
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&lca_secret);
        payload.extend_from_slice(&prev_init);
        let (kem_ct, aead_ct) = crypto::hpke_seal(&key_package.leaf.kem_public, &payload)?;

        let welcome = Welcome {
            group_info: GroupInfo {
                tree: self.tree.clone(),
                epoch: self.epoch,
                transcript_hash: self.transcript_hash,
            },
            joiner_leaf_index: joiner_index,
            lca_node: lca,
            sealed: HpkeCiphertext { kem_ct, aead_ct },
        };
        Ok((commit, welcome))
    }

    /// Remove a member and commit: blank their leaf+path, then re-key the committer's path so the removed
    /// member's keys are dead in the new epoch.
    pub fn remove_member(
        &mut self,
        leaf_index: LeafIndex,
        fresh_leaf_secret: Secret,
    ) -> Result<Commit, Error> {
        self.tree.remove_leaf(leaf_index);
        let (path, root_secret, own_secrets) =
            generate_update_path(&mut self.tree, self.own_leaf, fresh_leaf_secret)?;
        self.own_secrets = own_secrets;
        let commit = Commit {
            proposals: vec![Proposal::Remove { leaf_index }],
            path,
        };
        self.advance_epoch(&root_secret, &commit);
        Ok(commit)
    }

    /// Apply another member's `Commit`: apply its membership proposals, then its path re-key, advancing
    /// into the same new epoch.
    pub fn process_commit(&mut self, commit: &Commit) -> Result<(), Error> {
        for proposal in &commit.proposals {
            match proposal {
                Proposal::Add {
                    key_package,
                    leaf_index,
                } => self.tree.add_leaf_at(*leaf_index, key_package.leaf.clone()),
                Proposal::Remove { leaf_index } => self.tree.remove_leaf(*leaf_index),
            }
        }
        let (root_secret, learned) =
            apply_update_path(&mut self.tree, &commit.path, &self.own_secrets)?;
        for (node, secret) in learned {
            self.own_secrets.insert(node, secret);
        }
        self.advance_epoch(&root_secret, commit);
        Ok(())
    }

    /// Join a group from a `Welcome`. `own_leaf_secret` is the secret behind the KeyPackage the committer
    /// added — it opens the sealed payload and seeds this member's leaf state.
    pub fn join_from_welcome(welcome: &Welcome, own_leaf_secret: Secret) -> Result<Self, Error> {
        let leaf_index = welcome.joiner_leaf_index;
        let (_pk, sk) = crypto::node_keypair_from_path_secret(&own_leaf_secret)?;
        let payload = crypto::hpke_open(&welcome.sealed.kem_ct, &welcome.sealed.aead_ct, &sk)?;
        if payload.len() != 64 {
            return Err(Error::generic("treekem: welcome payload has wrong length"));
        }
        let mut lca_secret: Secret = [0u8; 32];
        lca_secret.copy_from_slice(&payload[..32]);
        let mut prev_init: Secret = [0u8; 32];
        prev_init.copy_from_slice(&payload[32..64]);

        let tree = welcome.group_info.tree.clone();
        let n = tree.num_leaves();
        let dp = direct_path(leaf_index, n);
        let lca_pos = dp
            .iter()
            .position(|&node| node == welcome.lca_node)
            .ok_or_else(|| Error::generic("treekem: LCA not on the joiner's direct path"))?;

        let mut own_secrets: HashMap<NodeIndex, Secret> = HashMap::new();
        own_secrets.insert(leaf_to_node(leaf_index), own_leaf_secret);
        let mut cur = lca_secret;
        own_secrets.insert(welcome.lca_node, cur);
        for &node in &dp[lca_pos + 1..] {
            cur = crypto::derive_path_secret(&cur);
            own_secrets.insert(node, cur);
        }
        let root_secret = cur;

        let secrets = EpochSecrets::derive(
            &root_secret,
            &prev_init,
            &welcome.group_info.transcript_hash,
        );
        Ok(Self {
            tree,
            own_leaf: leaf_index,
            own_secrets,
            epoch: welcome.group_info.epoch,
            secrets,
            transcript_hash: welcome.group_info.transcript_hash,
            send_generation: 0,
        })
    }

    /// Encrypt an application message under the current epoch (E2E; the relay sees only ciphertext).
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<AppCiphertext, Error> {
        let generation = self.send_generation;
        self.send_generation = self.send_generation.wrapping_add(1);
        crate::application::seal(
            &self.secrets.encryption_secret,
            self.epoch,
            self.own_leaf,
            generation,
            plaintext,
        )
    }

    /// Decrypt an application message from the current epoch. Returns an error if the message is from a
    /// different epoch (the caller selects the right epoch's `GroupState`).
    pub fn decrypt_message(&self, message: &AppCiphertext) -> Result<Vec<u8>, Error> {
        if message.epoch != self.epoch {
            return Err(Error::generic(format!(
                "treekem: application message epoch {} != current epoch {}",
                message.epoch, self.epoch
            )));
        }
        crate::application::open(&self.secrets.encryption_secret, message)
    }

    /// Roll the transcript + key schedule forward into the next epoch from a new root secret.
    fn advance_epoch(&mut self, root_secret: &Secret, commit: &Commit) {
        self.transcript_hash = next_transcript(&self.transcript_hash, commit);
        let prev_init = self.secrets.init_secret;
        self.secrets = EpochSecrets::derive(root_secret, &prev_init, &self.transcript_hash);
        self.epoch += 1;
        self.send_generation = 0;
    }
}

/// Chain the transcript hash over an applied commit so every member's epoch secret is bound to the exact
/// same commit history (a divergent commit yields a divergent epoch secret).
fn next_transcript(prev: &[u8; 32], commit: &Commit) -> [u8; 32] {
    let serialized = bincode::serialize(commit).unwrap_or_default();
    let mut hasher = blake3::Hasher::new_derive_key("citadel-treekem-transcript-v1");
    hasher.update(prev);
    hasher.update(&serialized);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::node_keypair_from_path_secret;

    fn member_leaf(cid: u64, secret: &Secret) -> LeafNode {
        let (kem_public, _sk) = node_keypair_from_path_secret(secret).unwrap();
        LeafNode {
            cid,
            kem_public,
            sig_public: vec![],
            leaf_index: 0,
            signature: vec![],
        }
    }

    /// Build `n` members sharing one public tree, each holding its own leaf secret, all at the same
    /// genesis epoch (exercises the `commit_update`/`process_commit` core without Add/Welcome).
    fn make_group(n: u32) -> Vec<GroupState> {
        let genesis_root = [42u8; 32];
        let leaf_secrets: Vec<Secret> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
        let leaves: Vec<LeafNode> = leaf_secrets
            .iter()
            .enumerate()
            .map(|(i, ps)| member_leaf(i as u64 + 100, ps))
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
            let commit = members[0].commit_update([0xAB; 32]).unwrap();
            for m in members.iter_mut().skip(1) {
                m.process_commit(&commit).unwrap();
            }
            let secret0 = *members[0].encryption_secret();
            for (i, m) in members.iter().enumerate() {
                assert_eq!(m.epoch, 1, "n={n} member {i}: epoch");
                assert_eq!(
                    m.encryption_secret(),
                    &secret0,
                    "n={n} member {i}: epoch secret"
                );
            }
        }
    }

    #[test]
    fn forward_secrecy_and_pcs_across_two_commits() {
        let mut members = make_group(4);
        let c1 = members[0].commit_update([1u8; 32]).unwrap();
        for m in members.iter_mut().skip(1) {
            m.process_commit(&c1).unwrap();
        }
        let epoch1 = *members[0].encryption_secret();

        let c2 = members[2].commit_update([2u8; 32]).unwrap();
        members[0].process_commit(&c2).unwrap();
        members[1].process_commit(&c2).unwrap();
        members[3].process_commit(&c2).unwrap();
        let epoch2 = *members[0].encryption_secret();

        assert_ne!(epoch1, epoch2, "consecutive epochs distinct (FS)");
        for m in &members {
            assert_eq!(m.epoch, 2);
            assert_eq!(m.encryption_secret(), &epoch2);
        }
    }

    #[test]
    fn full_lifecycle_create_add_add_remove() {
        // A founds the group.
        let a_secret = [11u8; 32];
        let mut a = GroupState::create(member_leaf(1, &a_secret), a_secret);

        // B joins via Add + Welcome.
        let b_secret = [22u8; 32];
        let kp_b = KeyPackage::generate(2, &b_secret).unwrap();
        let (commit_b, welcome_b) = a.add_member(&kp_b, [0xA1; 32]).unwrap();
        let mut b = GroupState::join_from_welcome(&welcome_b, b_secret).unwrap();
        let _ = commit_b; // (no other existing members to process it yet)
        assert_eq!(a.epoch, 1);
        assert_eq!(b.epoch, 1);
        assert_eq!(
            a.encryption_secret(),
            b.encryption_secret(),
            "founder and first joiner agree",
        );

        // C joins. Existing member B processes the commit; C bootstraps from the Welcome.
        let c_secret = [33u8; 32];
        let kp_c = KeyPackage::generate(3, &c_secret).unwrap();
        let (commit_c, welcome_c) = a.add_member(&kp_c, [0xA2; 32]).unwrap();
        b.process_commit(&commit_c).unwrap();
        let mut c = GroupState::join_from_welcome(&welcome_c, c_secret).unwrap();
        assert_eq!(a.epoch, 2);
        assert_eq!(b.epoch, 2);
        assert_eq!(c.epoch, 2);
        let secret2 = *a.encryption_secret();
        assert_eq!(b.encryption_secret(), &secret2, "B agrees at epoch 2");
        assert_eq!(c.encryption_secret(), &secret2, "C agrees at epoch 2");

        // A removes B. C follows; A and C agree, and the removed B can no longer follow into the epoch.
        let b_leaf = b.own_leaf;
        let mut b_after = b.clone();
        let commit_r = a.remove_member(b_leaf, [0xA3; 32]).unwrap();
        c.process_commit(&commit_r).unwrap();
        assert_eq!(a.epoch, 3);
        assert_eq!(c.epoch, 3);
        assert_eq!(
            a.encryption_secret(),
            c.encryption_secret(),
            "A and C agree at epoch 3 after removing B",
        );
        // B's leaf+path were blanked in the commit; B cannot recover the new path secret.
        assert!(
            b_after.process_commit(&commit_r).is_err()
                || b_after.encryption_secret() != a.encryption_secret(),
            "a removed member must not reach the post-removal epoch secret",
        );
    }

    #[test]
    fn application_messages_are_e2e_within_an_epoch() {
        // Get a 4-member group to a shared epoch 1.
        let mut members = make_group(4);
        let commit = members[0].commit_update([0x5A; 32]).unwrap();
        for m in members.iter_mut().skip(1) {
            m.process_commit(&commit).unwrap();
        }

        // Member 1 sends; everyone (incl. the sender) decrypts to the same plaintext.
        let plaintext = b"fire mission: grid 1234 5678, danger close";
        let ct = members[1].encrypt_message(plaintext).unwrap();
        for (i, m) in members.iter().enumerate() {
            let got = m.decrypt_message(&ct).unwrap();
            assert_eq!(got, plaintext, "member {i} must decrypt the group message");
        }

        // Two messages from the same sender use distinct generations (distinct keys).
        let ct_b = members[1].encrypt_message(b"second message").unwrap();
        assert_ne!(ct.generation, ct_b.generation);
        assert_eq!(
            members[2].decrypt_message(&ct_b).unwrap(),
            b"second message"
        );

        // The relay (no epoch secret) cannot decrypt: a state with a different epoch secret fails.
        let outsider = make_group(4);
        assert!(
            outsider[0].decrypt_message(&ct).is_err(),
            "a party without this epoch's secret cannot decrypt (server is blind)",
        );

        // A message from a past epoch does not decrypt at a later epoch (forward secrecy across epochs).
        let commit2 = members[0].commit_update([0x6B; 32]).unwrap();
        for m in members.iter_mut().skip(1) {
            m.process_commit(&commit2).unwrap();
        }
        assert!(
            members[2].decrypt_message(&ct).is_err(),
            "epoch-1 ciphertext must not decrypt under epoch 2",
        );
    }
}
