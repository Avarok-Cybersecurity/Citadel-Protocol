//! The Decentralized Hierarchy Encryption (DHE) half of the group CGKA coordinator: node-secret
//! assignment (owner → member, E2E-sealed), `DheEnvelope` message seal/open, and promote/demote.
//!
//! Child module of [`super`] so it reaches `GroupCgkaState`'s private fields. The owner is the
//! hierarchy root and the sole authority that assigns ranks; command paths never leave the owner node
//! except as KEM-sealed node secrets (a member learns only its own path + node secret).

use super::*;
use citadel_treekem::KeyPackage;
use citadel_types::proto::ReadPolicy;

impl GroupCgkaState {
    /// Owner-only: if a joiner has a pending rank, derive + seal its hierarchy assignment to its leaf
    /// KEM key (so only that member can open it). Used by [`GroupCgkaState::add_member`].
    pub(super) fn assignment_for_joiner(
        &self,
        kp: &KeyPackage,
    ) -> Result<Option<Vec<u8>>, NetworkError> {
        let Some(owner_h) = self.hierarchy_self.as_ref() else {
            return Ok(None);
        };
        let Some(path) = self.pending_ranks.get(&kp.leaf.cid) else {
            return Ok(None);
        };
        let member = owner_h.derive_descendant(path.clone())?;
        Ok(Some(member.seal_to(&kp.leaf.kem_public)?))
    }

    /// A member applies an assignment sealed to it by the owner, taking up its hierarchy position. This
    /// also switches the member's mode to `CommandHierarchy` (learned from the assignment's read
    /// policy), so its subsequent messages use the `DheEnvelope` path.
    pub fn apply_hierarchy_assignment(&mut self, sealed: &[u8]) -> Result<(), NetworkError> {
        let member = HierarchyMember::open(sealed, &self.own_leaf_secret)?;
        if !self.is_owner {
            self.hierarchy = GroupHierarchyMode::CommandHierarchy {
                read_policy: member.read_policy,
                ranks: HashMap::new(),
            };
        }
        self.hierarchy_self = Some(member);
        Ok(())
    }

    /// Owner-only: assign/raise `cid` to `path`. Returns the sealed assignment to deliver now if the
    /// member has already joined (otherwise it is applied when they join, via [`Self::add_member`]).
    pub fn promote(
        &mut self,
        cid: u64,
        path: CommandPath,
    ) -> Result<Option<Vec<u8>>, NetworkError> {
        if !self.is_owner {
            return Err(error!(ErrorCode::ProtoGroupCgkaNotOwner));
        }
        let member = {
            let owner_h = self
                .hierarchy_self
                .as_ref()
                .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?;
            owner_h.derive_descendant(path.clone())?
        };
        let _ = self.pending_ranks.insert(cid, path);
        let leaf_pk = self
            .group
            .as_ref()
            .and_then(|g| g.tree.leaf_of_cid(cid))
            .map(|leaf| leaf.kem_public.clone());
        match leaf_pk {
            Some(pk) => Ok(Some(member.seal_to(&pk)?)),
            None => Ok(None),
        }
    }

    /// Owner-only: revoke `cid`'s elevated rank. Rotates the hierarchy root (so the demoted member's old
    /// node secret can no longer derive any subtree), re-seals fresh assignments to every still-ranked
    /// member (the demoted one is isolated at a fresh leaf path — it can still self-send, but reads
    /// nothing it used to), and epoch-bumps the flat CGKA. Returns `(per-member sealed assignments,
    /// commit_bytes, new_epoch)`.
    #[allow(clippy::type_complexity)]
    pub fn demote(
        &mut self,
        cid: u64,
    ) -> Result<(Vec<(u64, Vec<u8>)>, Vec<u8>, u64), NetworkError> {
        if !self.is_owner {
            return Err(error!(ErrorCode::ProtoGroupCgkaNotOwner));
        }
        let read_policy = match &self.hierarchy {
            GroupHierarchyMode::CommandHierarchy { read_policy, .. } => *read_policy,
            GroupHierarchyMode::Flat => return Err(error!(ErrorCode::ProtoGroupCgkaNoState)),
        };
        // Isolate the demoted member at a fresh leaf path (loses its former subtree).
        let _ = self
            .pending_ranks
            .insert(cid, CommandPath(vec![format!("_demoted_{cid}")]));

        // Rotate the root so every previously-derived node secret is dead, then re-seal everyone.
        let new_root = HierarchyMember::root(fresh_secret(), read_policy);
        let ranks: Vec<(u64, CommandPath)> = self
            .pending_ranks
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let mut assignments = Vec::new();
        for (member_cid, path) in ranks {
            let leaf_pk = self
                .group
                .as_ref()
                .and_then(|g| g.tree.leaf_of_cid(member_cid))
                .map(|leaf| leaf.kem_public.clone());
            if let Some(pk) = leaf_pk {
                let member = new_root.derive_descendant(path)?;
                assignments.push((member_cid, member.seal_to(&pk)?));
            }
        }
        self.hierarchy_self = Some(new_root);

        // Epoch-bump the flat CGKA so the flat group key also rolls forward.
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?;
        let commit = group.commit_update(fresh_secret())?;
        let epoch = group.epoch;
        let commit_bytes = commit
            .serialize_to_vector()
            .map_err(|_| ser_err("commit"))?;
        Ok((assignments, commit_bytes, epoch))
    }

    /// The flat group key to use for the DHE flat-wrap, present only under `BroadcastAudit`.
    fn flat_key_for_policy(&self) -> Option<Secret> {
        match &self.hierarchy {
            GroupHierarchyMode::CommandHierarchy {
                read_policy: ReadPolicy::BroadcastAudit,
                ..
            } => self.group.as_ref().map(|g| *g.encryption_secret()),
            _ => None,
        }
    }

    /// Seal an outbound message as a `DheEnvelope` (superiors of the sender can read it).
    pub(super) fn encrypt_dhe(&self, plaintext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        let member = self
            .hierarchy_self
            .as_ref()
            .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?;
        let flat = self.flat_key_for_policy();
        let content_key = fresh_secret();
        member.seal_message(flat.as_ref(), &content_key, plaintext)
    }

    /// Open an inbound `DheEnvelope` (as a superior of the sender, or via the flat key in audit mode).
    pub(super) fn decrypt_dhe(&self, ciphertext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        let member = self
            .hierarchy_self
            .as_ref()
            .ok_or_else(|| error!(ErrorCode::ProtoGroupCgkaNoState))?;
        let flat = self.flat_key_for_policy();
        member.open_message(flat.as_ref(), ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_types::proto::{GroupHierarchyMode, ReadPolicy};
    use std::collections::HashMap;

    fn hierarchy_mode(ranks: &[(u64, &str)]) -> GroupHierarchyMode {
        let mut map = HashMap::new();
        for (cid, path) in ranks {
            let _ = map.insert(*cid, CommandPath::parse(path));
        }
        GroupHierarchyMode::CommandHierarchy {
            read_policy: ReadPolicy::SuperiorOnly,
            ranks: map,
        }
    }

    /// Owner assigns ranks at create; a subordinate's message is readable by its superior and the root,
    /// but not by a sibling. Then a promotion grants a newcomer subtree access.
    #[test]
    fn superior_reads_subordinate_and_promotion_grants_access() {
        // Owner (root) with B=/alpha (superior) and C=/alpha/bravo (subordinate).
        let mode = hierarchy_mode(&[(2, "/alpha"), (3, "/alpha/bravo"), (4, "/charlie")]);
        let mut owner = GroupCgkaState::new_owner(1, mode.clone()).unwrap();

        let join = |cid: u64| GroupCgkaState::new_joiner(cid, mode.clone()).unwrap();
        let (mut b, kp_b) = join(2);
        let (mut c, kp_c) = join(3);
        let (mut d, kp_d) = join(4); // sibling subtree /charlie

        let (wb, _cb, _e, ab) = owner.add_member(&kp_b).unwrap();
        b.join(&wb).unwrap();
        b.apply_hierarchy_assignment(&ab.unwrap()).unwrap();

        let (wc, cc, ec, ac) = owner.add_member(&kp_c).unwrap();
        b.process_commit(&cc, ec).unwrap();
        c.join(&wc).unwrap();
        c.apply_hierarchy_assignment(&ac.unwrap()).unwrap();

        let (wd, cd, ed, ad) = owner.add_member(&kp_d).unwrap();
        b.process_commit(&cd, ed).unwrap();
        c.process_commit(&cd, ed).unwrap();
        d.join(&wd).unwrap();
        d.apply_hierarchy_assignment(&ad.unwrap()).unwrap();

        // C (subordinate) sends. B (superior) and the owner (root) read it; D (sibling) cannot.
        let wire = c.encrypt_message(b"sitrep from bravo").unwrap();
        assert_eq!(b.decrypt_message(&wire).unwrap(), b"sitrep from bravo");
        assert_eq!(owner.decrypt_message(&wire).unwrap(), b"sitrep from bravo");
        assert!(d.decrypt_message(&wire).is_err(), "sibling cannot read");

        // Promote D under /alpha; D now reads C's subtree.
        let sealed = owner
            .promote(4, CommandPath::parse("/alpha/delta"))
            .unwrap();
        d.apply_hierarchy_assignment(&sealed.unwrap()).unwrap();
        let wire2 = c.encrypt_message(b"second sitrep").unwrap();
        // D at /alpha/delta is a sibling of /alpha/bravo, still cannot read C; but B (/alpha) still can.
        assert!(d.decrypt_message(&wire2).is_err());
        assert_eq!(b.decrypt_message(&wire2).unwrap(), b"second sitrep");
    }

    /// After demotion, the demoted superior can no longer read a former subordinate's new messages.
    #[test]
    fn demotion_revokes_future_reads() {
        let mode = hierarchy_mode(&[(2, "/alpha"), (3, "/alpha/bravo")]);
        let mut owner = GroupCgkaState::new_owner(1, mode.clone()).unwrap();

        let (mut b, kp_b) = GroupCgkaState::new_joiner(2, mode.clone()).unwrap();
        let (mut c, kp_c) = GroupCgkaState::new_joiner(3, mode.clone()).unwrap();
        let (wb, _cb, _e, ab) = owner.add_member(&kp_b).unwrap();
        b.join(&wb).unwrap();
        b.apply_hierarchy_assignment(&ab.unwrap()).unwrap();
        let (wc, cc, ec, ac) = owner.add_member(&kp_c).unwrap();
        b.process_commit(&cc, ec).unwrap();
        c.join(&wc).unwrap();
        c.apply_hierarchy_assignment(&ac.unwrap()).unwrap();

        // Before demotion, B reads C.
        let pre = c.encrypt_message(b"before").unwrap();
        assert_eq!(b.decrypt_message(&pre).unwrap(), b"before");

        // Demote B: rotate + reseal. B and C apply their new assignments + the epoch-bump commit.
        let (assignments, commit, epoch) = owner.demote(2).unwrap();
        b.process_commit(&commit, epoch).unwrap();
        c.process_commit(&commit, epoch).unwrap();
        for (cid, sealed) in assignments {
            if cid == 2 {
                b.apply_hierarchy_assignment(&sealed).unwrap();
            } else if cid == 3 {
                c.apply_hierarchy_assignment(&sealed).unwrap();
            }
        }

        // After demotion, B can no longer read C's new traffic; the owner (root) still can.
        let post = c.encrypt_message(b"after").unwrap();
        assert!(
            b.decrypt_message(&post).is_err(),
            "demoted superior loses future reads"
        );
        assert_eq!(owner.decrypt_message(&post).unwrap(), b"after");
    }
}
