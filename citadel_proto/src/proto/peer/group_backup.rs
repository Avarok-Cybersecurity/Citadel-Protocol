//! A member's group state, kept by the server sealed under a key only the account's devices hold,
//! so the account takes its groups along when it moves to a new device.
//!
//! The key is the account's RE-VFS key (`RevfsKeySource`), which the application derives from the
//! account's recovery or identity seed: a device recovered with the account's phrase derives the
//! same key, and no server ever holds it. Each group's state is one sealed object under that key,
//! its object id in a domain of its own ([`object_id`]), so a state sealed for one group never
//! opens as another's, nor as any file the account stores.
//!
//! The server keeps one sealed state per member and group (member, group owner,
//! [`GROUP_BACKUP_MAP`], mgid), within the group mail byte cap, and hands it back to the member's
//! own session when that session holds no state of its own. A state restored this way is one
//! another device of the account also held, so the member replaces its leaf as soon as it is back
//! (see `GroupCgkaState::needs_new_leaf`).

use crate::error::NetworkError;
use citadel_crypt::revfs_seal::{self, RevfsKey};
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::MessageGroupKey;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

/// The byte map the server keeps members' sealed group states in.
pub const GROUP_BACKUP_MAP: &str = "group_backup";

const OBJECT_LABEL: &[u8] = b"citadel-group-state-backup-v1";

/// One layer: the seal's own AEAD carries the confidentiality, and the state is re-sealed whole
/// on every change, so more layers would only multiply the bytes sent.
const LEVEL: SecurityLevel = SecurityLevel::Standard;

/// The object id `key`'s state is sealed under.
pub fn object_id(key: MessageGroupKey) -> u128 {
    let digest = Sha3_256::new()
        .chain_update(OBJECT_LABEL)
        .chain_update(key.cid.to_be_bytes())
        .chain_update(key.mgid.to_be_bytes())
        .finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    u128::from_be_bytes(id)
}

/// `state` (an exported group state) sealed for the server to keep.
pub fn seal(
    account_key: &RevfsKey,
    key: MessageGroupKey,
    state: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    revfs_seal::seal(account_key, object_id(key), 0, LEVEL, state)
        .map_err(|err| NetworkError::msg(format!("Unable to seal the state of {key:?}: {err}")))
}

/// The state `sealed` holds, if it was sealed for `key` under `account_key`.
pub fn open(
    account_key: &RevfsKey,
    cid: u64,
    key: MessageGroupKey,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, NetworkError> {
    revfs_seal::open(Some(account_key), cid, object_id(key), 0, LEVEL, sealed)
        .map(Zeroizing::new)
        .map_err(|err| {
            NetworkError::msg(format!("Unable to open the kept state of {key:?}: {err}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: MessageGroupKey = MessageGroupKey { cid: 10, mgid: 7 };

    fn account_key(root: u8) -> RevfsKey {
        RevfsKey::derive(&[root; 32], "localhost", 20).unwrap()
    }

    #[test]
    fn a_kept_state_opens_only_for_its_group_under_its_account_key() {
        let state = b"exported group state".to_vec();
        let sealed = seal(&account_key(1), KEY, &state).unwrap();
        assert!(!sealed.windows(state.len()).any(|w| w == state.as_slice()));
        assert_eq!(
            open(&account_key(1), 20, KEY, &sealed).unwrap().as_slice(),
            state
        );

        assert!(
            open(&account_key(2), 20, KEY, &sealed).is_err(),
            "another seed"
        );
        let other = MessageGroupKey { cid: 10, mgid: 8 };
        assert!(
            open(&account_key(1), 20, other, &sealed).is_err(),
            "another group"
        );
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            open(&account_key(1), 20, KEY, &tampered).is_err(),
            "altered"
        );
    }
}
