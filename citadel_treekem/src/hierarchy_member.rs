//! Per-member **Decentralized Hierarchy Encryption** session state: a member's `CommandPath`, its
//! node secret, and the group `ReadPolicy`. This is the runtime companion to [`crate::hierarchy`] —
//! it distributes node secrets (the owner seals each member's assignment to that member's leaf KEM
//! key) and seals/opens [`DheEnvelope`] application messages, dispatching superior-vs-member reads.
//!
//! All randomness (the root secret, per-message content keys) is supplied by the caller so this layer
//! stays deterministic and unit-testable; the proto coordinator draws it from a CSPRNG.

use crate::crypto::{self, Secret};
use crate::hierarchy::{CommandPath, DheEnvelope, HierarchyScheme, KdfKemTree, ReadPolicy};
use citadel_types::errors::Error;
use serde::{Deserialize, Serialize};

/// One member's hierarchy session: where it sits in the command tree and the secret that lets it (and
/// its superiors) read its subtree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HierarchyMember {
    /// This member's position in the command hierarchy.
    pub path: CommandPath,
    /// This member's node secret (an ancestor can derive any descendant's; nobody can derive upward).
    pub node_secret: Secret,
    /// The group read policy (whether ordinary members read via the flat group key).
    pub read_policy: ReadPolicy,
}

impl HierarchyMember {
    /// The root authority (the group owner): `path = /`, holding the randomly-drawn `root_secret` from
    /// which every member's node secret descends.
    pub fn root(root_secret: Secret, read_policy: ReadPolicy) -> Self {
        Self {
            path: CommandPath::root(),
            node_secret: root_secret,
            read_policy,
        }
    }

    /// Owner-only: derive a descendant member's assignment for `descendant_path` (must be within this
    /// holder's subtree).
    pub fn derive_descendant(&self, descendant_path: CommandPath) -> Result<Self, Error> {
        let node_secret =
            KdfKemTree.derive_descendant_secret(&self.node_secret, &self.path, &descendant_path)?;
        Ok(Self {
            path: descendant_path,
            node_secret,
            read_policy: self.read_policy,
        })
    }

    /// Owner-only: seal this assignment to a member's leaf KEM public key (from their KeyPackage), so
    /// only the holder of the matching leaf secret can open it.
    pub fn seal_to(&self, leaf_kem_public: &[u8]) -> Result<Vec<u8>, Error> {
        let plaintext = bincode::serialize(self)
            .map_err(|err| Error::generic(format!("DHE assignment serialize failed: {err}")))?;
        let (kem_ct, aead_ct) = crypto::hpke_seal(leaf_kem_public, &plaintext)?;
        let sealed = SealedAssignment { kem_ct, aead_ct };
        bincode::serialize(&sealed)
            .map_err(|err| Error::generic(format!("DHE sealed assignment serialize failed: {err}")))
    }

    /// Member: open an assignment that was sealed to this member's leaf (its `own_leaf_secret` from the
    /// KeyPackage it published).
    pub fn open(sealed_bytes: &[u8], own_leaf_secret: &Secret) -> Result<Self, Error> {
        let sealed: SealedAssignment = bincode::deserialize(sealed_bytes)
            .map_err(|err| Error::generic(format!("DHE sealed assignment parse failed: {err}")))?;
        let (_pk, sk) = crypto::node_keypair_from_path_secret(own_leaf_secret)?;
        let plaintext = crypto::hpke_open(&sealed.kem_ct, &sealed.aead_ct, &sk)?;
        bincode::deserialize(&plaintext)
            .map_err(|err| Error::generic(format!("DHE assignment parse failed: {err}")))
    }

    /// Seal an application message as this member. `flat_group_key` is required iff the policy is
    /// [`ReadPolicy::BroadcastAudit`]; `content_key` is a fresh per-message key from the caller.
    pub fn seal_message(
        &self,
        flat_group_key: Option<&Secret>,
        content_key: &Secret,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let env = DheEnvelope::seal(
            &KdfKemTree,
            &self.path,
            &self.node_secret,
            flat_group_key,
            self.read_policy,
            content_key,
            plaintext,
        )?;
        bincode::serialize(&env)
            .map_err(|err| Error::generic(format!("DHE envelope serialize failed: {err}")))
    }

    /// Open an application message: as a **superior** (or the sender) when this member is an ancestor of
    /// the sender, otherwise (in `BroadcastAudit`) as an ordinary flat-group member.
    pub fn open_message(
        &self,
        flat_group_key: Option<&Secret>,
        wire: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let env: DheEnvelope = bincode::deserialize(wire)
            .map_err(|err| Error::generic(format!("DHE envelope parse failed: {err}")))?;
        if self.path.is_ancestor_of(&env.sender_path) {
            env.open_as_superior(&KdfKemTree, &self.path, &self.node_secret)
        } else if let Some(flat) = flat_group_key {
            env.open_as_member(flat)
        } else {
            Err(Error::generic(
                "DHE: not a superior of the sender and no flat-group read (superior-only mode)",
            ))
        }
    }
}

/// An HPKE-sealed assignment (KEM ciphertext + AEAD ciphertext) on the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SealedAssignment {
    kem_ct: Vec<u8>,
    aead_ct: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assign(
        owner: &HierarchyMember,
        path: &str,
        leaf_secret: &Secret,
    ) -> (HierarchyMember, Vec<u8>) {
        let member = owner.derive_descendant(CommandPath::parse(path)).unwrap();
        let (leaf_pk, _sk) = crypto::node_keypair_from_path_secret(leaf_secret).unwrap();
        let sealed = member.seal_to(&leaf_pk).unwrap();
        (member, sealed)
    }

    #[test]
    fn superior_reads_subordinate_via_distributed_assignments() {
        let owner = HierarchyMember::root([7u8; 32], ReadPolicy::SuperiorOnly);

        // Bn1 and its subordinate Co-A each receive a sealed assignment opened with their leaf secret.
        let bn1_leaf = [1u8; 32];
        let (_bn1_sent, bn1_sealed) = assign(&owner, "/HQ/Bn1", &bn1_leaf);
        let bn1 = HierarchyMember::open(&bn1_sealed, &bn1_leaf).unwrap();

        let coa_leaf = [2u8; 32];
        let (_coa_sent, coa_sealed) = assign(&owner, "/HQ/Bn1/Co-A", &coa_leaf);
        let coa = HierarchyMember::open(&coa_sealed, &coa_leaf).unwrap();

        // Co-A sends; its superior Bn1 reads, the root reads, a sibling cannot.
        let wire = coa.seal_message(None, &[0x42; 32], b"sitrep").unwrap();
        assert_eq!(bn1.open_message(None, &wire).unwrap(), b"sitrep");
        assert_eq!(owner.open_message(None, &wire).unwrap(), b"sitrep");

        let cob_leaf = [3u8; 32];
        let (_x, cob_sealed) = assign(&owner, "/HQ/Bn1/Co-B", &cob_leaf);
        let cob = HierarchyMember::open(&cob_sealed, &cob_leaf).unwrap();
        assert!(
            cob.open_message(None, &wire).is_err(),
            "sibling cannot read"
        );

        // A subordinate cannot read a superior's message.
        let from_bn1 = bn1.seal_message(None, &[0x43; 32], b"orders").unwrap();
        assert!(coa.open_message(None, &from_bn1).is_err());
    }

    #[test]
    fn broadcast_audit_lets_members_read_and_superiors_audit() {
        let owner = HierarchyMember::root([8u8; 32], ReadPolicy::BroadcastAudit);
        let flat = [9u8; 32];

        let coa_leaf = [2u8; 32];
        let (_s, coa_sealed) = assign(&owner, "/HQ/Bn1/Co-A", &coa_leaf);
        let coa = HierarchyMember::open(&coa_sealed, &coa_leaf).unwrap();

        let cob_leaf = [3u8; 32];
        let (_s2, cob_sealed) = assign(&owner, "/HQ/Bn1/Co-B", &cob_leaf);
        let cob = HierarchyMember::open(&cob_sealed, &cob_leaf).unwrap();

        // Co-A sends in broadcast+audit: a sibling reads via the flat key; the root audits via hierarchy.
        let wire = coa
            .seal_message(Some(&flat), &[0x55; 32], b"net traffic")
            .unwrap();
        assert_eq!(
            cob.open_message(Some(&flat), &wire).unwrap(),
            b"net traffic"
        );
        assert_eq!(
            owner.open_message(Some(&flat), &wire).unwrap(),
            b"net traffic"
        );
    }
}
