//! Sealing RE-VFS groups under the account's own key (format v2).
//!
//! A stored object is sealed group by group, before it leaves the device, under a key derived
//! from a root only the account's devices hold. The server stores and returns opaque bytes.
//!
//! ```text
//! group  = "RVF2" ‖ key_id (8) ‖ level (1) ‖ layer[level]
//! layer[0]  = nonce (24) ‖ XChaCha20-Poly1305(k[0], nonce, aad(0), plaintext)
//! layer[n]  = nonce (24) ‖ XChaCha20-Poly1305(k[n], nonce, aad(n), layer[n - 1])
//! k[n]      = HKDF-SHA3-256(k_revfs, object_id ‖ n)
//! aad(n)    = "RVF2" ‖ key_id ‖ object_id ‖ group_index ‖ level ‖ n
//! ```
//!
//! The additional data binds every group to its object and position, so a group moved to
//! another object or position does not open. A group without the prefix is refused
//! (`RevfsSealUnrecognised`), and one under another key's id is refused
//! (`RevfsSealedUnderAnotherKey`).
//!
//! Pure: no I/O, no key storage.

mod key;

pub use key::{domain_bound_info, RevfsKey, RevfsKeySource, RevfsKeys, KEY_ID_LEN};

use crate::misc::CryptError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use citadel_io::ErrorCode;
use citadel_types::crypto::{check_structural, SecurityLevel};
use rand::RngCore;

/// The prefix of every v2 group.
pub const MAGIC: &[u8; 4] = b"RVF2";
const HEADER_LEN: usize = MAGIC.len() + KEY_ID_LEN + 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const LAYER_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// The length of a sealed group: the same for every group of a given size and level, which the
/// stored object's fixed group boundaries rely on.
pub fn sealed_len(plaintext_len: usize, level: SecurityLevel) -> usize {
    HEADER_LEN + (level.value() as usize + 1) * LAYER_OVERHEAD + plaintext_len
}

/// Seals one group of an object. `level` is the object's level: `level + 1` layers.
pub fn seal(
    key: &RevfsKey,
    object_id: u128,
    group_index: u64,
    level: SecurityLevel,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptError> {
    let layers = layer_count(level)?;
    let mut inner = plaintext.to_vec();
    for layer in 0..layers {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let aad = additional_data(key, object_id, group_index, level, layer);
        let cipher = XChaCha20Poly1305::new(key.layer_key(object_id, layer).as_slice().into());
        let sealed = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &inner,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptError::encrypt("RE-VFS group seal failed"))?;
        inner = Vec::with_capacity(NONCE_LEN + sealed.len());
        inner.extend_from_slice(&nonce);
        inner.extend_from_slice(&sealed);
    }
    let mut out = Vec::with_capacity(HEADER_LEN + inner.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&key.id());
    out.push(level.value());
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Opens one stored group under this account's key. `level` is the object's level as its
/// metadata states it; a group naming another level is refused.
pub fn open(
    key: Option<&RevfsKey>,
    cid: u64,
    object_id: u128,
    group_index: u64,
    level: SecurityLevel,
    group: &[u8],
) -> Result<Vec<u8>, CryptError> {
    if group.len() < HEADER_LEN || &group[..MAGIC.len()] != MAGIC {
        return Err(citadel_io::error!(
            ErrorCode::RevfsSealUnrecognised,
            object_id,
            group_index
        ));
    }
    let key = key.ok_or_else(|| citadel_io::error!(ErrorCode::RevfsKeyMissing, cid))?;
    if group[MAGIC.len()..HEADER_LEN - 1] != key.id() {
        return Err(citadel_io::error!(ErrorCode::RevfsSealedUnderAnotherKey));
    }
    let stated = group[HEADER_LEN - 1];
    if stated != level.value() {
        return Err(citadel_io::error!(
            ErrorCode::RevfsSealLevelMismatch,
            stated,
            level.value()
        ));
    }
    let broken = || citadel_io::error!(ErrorCode::RevfsSealBroken, object_id, group_index);
    let layers = layer_count(level)?;
    let mut inner = group[HEADER_LEN..].to_vec();
    for layer in (0..layers).rev() {
        if inner.len() < LAYER_OVERHEAD {
            return Err(broken());
        }
        let aad = additional_data(key, object_id, group_index, level, layer);
        let cipher = XChaCha20Poly1305::new(key.layer_key(object_id, layer).as_slice().into());
        inner = cipher
            .decrypt(
                XNonce::from_slice(&inner[..NONCE_LEN]),
                Payload {
                    msg: &inner[NONCE_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| broken())?;
    }
    Ok(inner)
}

fn layer_count(level: SecurityLevel) -> Result<u8, CryptError> {
    check_structural(level).map_err(|err| {
        citadel_io::error!(ErrorCode::SecurityLevelAboveMaximum, err.level, err.maximum)
    })?;
    Ok(level.value() + 1)
}

fn additional_data(
    key: &RevfsKey,
    object_id: u128,
    group_index: u64,
    level: SecurityLevel,
    layer: u8,
) -> [u8; HEADER_LEN + 16 + 8 + 1] {
    let mut aad = [0u8; HEADER_LEN + 16 + 8 + 1];
    aad[..4].copy_from_slice(MAGIC);
    aad[4..12].copy_from_slice(&key.id());
    aad[12..28].copy_from_slice(&object_id.to_be_bytes());
    aad[28..36].copy_from_slice(&group_index.to_be_bytes());
    aad[36] = level.value();
    aad[37] = layer;
    aad
}

#[cfg(test)]
mod tests;
