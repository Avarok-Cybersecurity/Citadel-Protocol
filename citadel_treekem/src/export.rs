//! A member's state, written out so it outlives the process that holds it, and read back.
//!
//! The bytes are every secret the member holds for the group, so whoever stores them must keep
//! them as it keeps the account's own keys. Nothing in them is shared with another member.
//!
//! A state read back never sends under the incarnation it was written with: [`GroupState::import`]
//! takes a fresh one, and its generations start again at 0 under it (see
//! [`crate::AppCiphertext::incarnation`]). The frames it had opened stay opened.

use crate::crypto::{Secret, SecretMap};
use crate::group::GroupState;
use crate::replay::OpenedFrames;
use crate::schedule::EpochSecrets;
use crate::tree::math::{LeafIndex, NodeIndex};
use crate::tree::ratchet_tree::RatchetTree;
use citadel_types::errors::Error;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize, Zeroize)]
struct ExportedSecrets {
    epoch_secret: Secret,
    encryption_secret: Secret,
    confirmation_key: Secret,
    membership_key: Secret,
    init_secret: Secret,
    own_secrets: Vec<(NodeIndex, Secret)>,
    readable_past_epochs: Vec<(u64, Secret)>,
    signing_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Exported {
    tree: RatchetTree,
    own_leaf: LeafIndex,
    epoch: u64,
    transcript_hash: [u8; 32],
    opened: OpenedFrames,
    secrets: ExportedSecrets,
}

impl GroupState {
    /// This member's whole state, to be read back by [`Self::import`].
    pub fn export(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut secrets = ExportedSecrets {
            epoch_secret: self.secrets.epoch_secret,
            encryption_secret: self.secrets.encryption_secret,
            confirmation_key: self.secrets.confirmation_key,
            membership_key: self.secrets.membership_key,
            init_secret: self.secrets.init_secret,
            own_secrets: self.own_secrets.iter().map(|(n, s)| (*n, *s)).collect(),
            readable_past_epochs: self.readable_past_epochs.clone(),
            signing_key: self.signing_key.to_vec(),
        };
        let exported = Exported {
            tree: self.tree.clone(),
            own_leaf: self.own_leaf,
            epoch: self.epoch,
            transcript_hash: self.transcript_hash,
            opened: self.opened.clone(),
            secrets: ExportedSecrets {
                own_secrets: std::mem::take(&mut secrets.own_secrets),
                readable_past_epochs: std::mem::take(&mut secrets.readable_past_epochs),
                signing_key: std::mem::take(&mut secrets.signing_key),
                ..secrets
            },
        };
        let bytes = bincode::serialize(&exported)
            .map_err(|err| Error::generic(format!("treekem: state export failed: {err}")));
        let Exported { mut secrets, .. } = exported;
        secrets.zeroize();
        bytes.map(Zeroizing::new)
    }

    /// A state written by [`Self::export`], sending under `incarnation`, which must differ from
    /// every incarnation this state sent under before.
    pub fn import(bytes: &[u8], incarnation: u64) -> Result<Self, Error> {
        let Exported {
            tree,
            own_leaf,
            epoch,
            transcript_hash,
            opened,
            mut secrets,
        } = citadel_io::decode::deserialize(bytes)
            .map_err(|err| Error::generic(format!("treekem: state import failed: {err}")))?;
        tree.validate()?;
        let mut own_secrets = SecretMap::default();
        for (node, secret) in secrets.own_secrets.iter() {
            own_secrets.insert(*node, *secret);
        }
        let epoch_secrets = EpochSecrets {
            epoch_secret: secrets.epoch_secret,
            encryption_secret: secrets.encryption_secret,
            confirmation_key: secrets.confirmation_key,
            membership_key: secrets.membership_key,
            init_secret: secrets.init_secret,
        };
        let state = GroupState {
            tree,
            own_leaf,
            own_secrets,
            epoch,
            secrets: epoch_secrets,
            transcript_hash,
            send_generation: 0,
            readable_past_epochs: std::mem::take(&mut secrets.readable_past_epochs),
            signing_key: Zeroizing::new(std::mem::take(&mut secrets.signing_key)),
            opened,
            incarnation,
        };
        secrets.zeroize();
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use crate::{GroupState, KeyPackage};

    #[test]
    fn a_state_read_back_reads_and_sends_and_never_reopens() {
        let a_secret = [1u8; 32];
        let mut a = GroupState::create(KeyPackage::generate(1, &a_secret).unwrap().leaf, a_secret);
        let b_secret = [2u8; 32];
        let (_, welcome) = a
            .add_member(&KeyPackage::generate(2, &b_secret).unwrap(), [3u8; 32])
            .unwrap();
        let mut b = GroupState::join_from_welcome(&welcome, b_secret).unwrap();
        let first = a.encrypt_message(b"before").unwrap();
        assert_eq!(b.decrypt_message(&first).unwrap().plaintext, b"before");

        let mut b = GroupState::import(&b.export().unwrap(), 7).unwrap();
        assert!(
            b.decrypt_message(&first).is_err(),
            "opened before it was written out"
        );
        let later = a.encrypt_message(b"after").unwrap();
        assert_eq!(b.decrypt_message(&later).unwrap().plaintext, b"after");
        let reply = b.encrypt_message(b"reply").unwrap();
        assert_eq!((reply.incarnation, reply.generation), (7, 0));
        assert_eq!(a.decrypt_message(&reply).unwrap().sender_cid, 2);
    }
}
