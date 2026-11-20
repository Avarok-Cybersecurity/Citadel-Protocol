//! The account's RE-VFS key, and the port it reaches a node through.
//!
//! The key is derived from a root only the account's devices hold (its recovery or identity
//! seed), so no server ever holds it. The node never stores or generates a root: the
//! application hands it keys through [`RevfsKeySource`].

use crate::misc::CryptError;
use citadel_io::ErrorCode;
use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use zeroize::Zeroizing;

const KEY_SALT: &[u8] = b"citadel-revfs-local-v1";
const KEY_ID_LABEL: &[u8] = b"citadel-revfs-key-id-v1";
const OBJECT_SALT: &[u8] = b"citadel-revfs-object-v1";

/// The length of a key id on every sealed group.
pub const KEY_ID_LEN: usize = 8;

/// One account's key for the objects it stores on one server.
#[derive(Clone)]
pub struct RevfsKey {
    key: Arc<Zeroizing<[u8; 32]>>,
    id: [u8; KEY_ID_LEN],
}

impl RevfsKey {
    /// `root` is the account's recovery or identity seed. `canonical_domain` is the server's
    /// domain, canonicalised by the caller as for the recovery phrase, so one root's keys on two
    /// servers are unrelated. `cid` is the account on that server.
    pub fn derive(root: &[u8; 32], canonical_domain: &str, cid: u64) -> Result<Self, CryptError> {
        let info = domain_bound_info(canonical_domain, &cid.to_be_bytes())
            .ok_or_else(|| citadel_io::error!(ErrorCode::RevfsKeyDomainInvalid))?;
        let mut key = Zeroizing::new([0u8; 32]);
        expand(KEY_SALT, root, &info, &mut key);
        let digest = Sha3_256::new()
            .chain_update(KEY_ID_LABEL)
            .chain_update(key.as_slice())
            .finalize();
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&digest[..KEY_ID_LEN]);
        Ok(Self {
            key: Arc::new(key),
            id,
        })
    }

    /// The id every group sealed under this key carries; it reveals nothing about the key.
    pub fn id(&self) -> [u8; KEY_ID_LEN] {
        self.id
    }

    /// The subkey for one layer of one object.
    pub(super) fn layer_key(&self, object_id: u128, layer: u8) -> Zeroizing<[u8; 32]> {
        let mut info = [0u8; 17];
        info[..16].copy_from_slice(&object_id.to_be_bytes());
        info[16] = layer;
        let mut out = Zeroizing::new([0u8; 32]);
        expand(OBJECT_SALT, self.key.as_slice(), &info, &mut out);
        out
    }
}

/// The HKDF `info` that binds a key derived from an account's seed to one server and one account
/// there: `u16be(len(domain)) ‖ domain ‖ 0x00 ‖ account`. The RE-VFS key and the recovery phrase's
/// factor both use it, so one seed's keys on two servers are unrelated. `None` for a domain that
/// is empty or longer than 65535 bytes.
pub fn domain_bound_info(canonical_domain: &str, account: &[u8]) -> Option<Vec<u8>> {
    let domain_len = u16::try_from(canonical_domain.len())
        .ok()
        .filter(|len| *len > 0)?;
    let mut info = Vec::with_capacity(2 + canonical_domain.len() + 1 + account.len());
    info.extend_from_slice(&domain_len.to_be_bytes());
    info.extend_from_slice(canonical_domain.as_bytes());
    info.push(0);
    info.extend_from_slice(account);
    Some(info)
}

fn expand(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8; 32]) {
    // 32 bytes is within HKDF-SHA3-256's 255 * 32 limit, so expansion cannot fail.
    Hkdf::<Sha3_256>::new(Some(salt), ikm)
        .expand(info, out)
        .unwrap_or_else(|_| unreachable!("32 bytes is a valid HKDF-SHA3-256 output length"));
}

impl Debug for RevfsKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RevfsKey(id {:02x?})", self.id)
    }
}

/// Where a node gets an account's RE-VFS key. `None` means the account has none here: a push
/// fails with [`ErrorCode::RevfsKeyMissing`], and only objects sealed before keys existed open.
pub trait RevfsKeySource: Send + Sync {
    fn revfs_key(&self, cid: u64) -> Option<RevfsKey>;
}

impl<F: Fn(u64) -> Option<RevfsKey> + Send + Sync> RevfsKeySource for F {
    fn revfs_key(&self, cid: u64) -> Option<RevfsKey> {
        self(cid)
    }
}

/// A node's key source, shared by its sessions.
pub type RevfsKeys = Arc<dyn RevfsKeySource>;
