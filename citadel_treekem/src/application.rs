//! Application messages: per-epoch, per-sender, per-message AEAD keyed off the group `encryption_secret`.
//!
//! Every member can derive *any* sender's message key for a given generation from the shared epoch
//! `encryption_secret` (an MLS "secret-tree"-style derivation), so a sender just tags each ciphertext
//! with `(sender, generation)` and recipients derive the matching key. Per-message keys give forward
//! secrecy within an epoch (a used generation's key can be dropped); the relay sees only ciphertext.

use crate::crypto::Secret;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use citadel_types::errors::Error;
use serde::{Deserialize, Serialize};

/// An end-to-end-encrypted group application message. The relay forwards this verbatim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppCiphertext {
    /// The epoch this message was encrypted under.
    pub epoch: u64,
    /// The sender's leaf index.
    pub sender: u32,
    /// Per-sender message counter (the "generation").
    pub generation: u32,
    /// AEAD ciphertext (ChaCha20-Poly1305).
    pub ciphertext: Vec<u8>,
}

/// The message key + nonce for `(sender, generation)` under `encryption_secret`. Deterministic for all
/// members, so any recipient derives the sender's key.
fn message_key_nonce(
    encryption_secret: &Secret,
    sender: u32,
    generation: u32,
) -> ([u8; 32], [u8; 12]) {
    let mut hasher = blake3::Hasher::new_derive_key("citadel-treekem-app-message-v1");
    hasher.update(encryption_secret);
    hasher.update(&sender.to_be_bytes());
    hasher.update(&generation.to_be_bytes());
    let mut out = [0u8; 44];
    hasher.finalize_xof().fill(&mut out);
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out[32..44]);
    (key, nonce)
}

/// Seal `plaintext` under the `(sender, generation)` message key.
pub(crate) fn seal(
    encryption_secret: &Secret,
    epoch: u64,
    sender: u32,
    generation: u32,
    plaintext: &[u8],
) -> Result<AppCiphertext, Error> {
    let (key, nonce) = message_key_nonce(encryption_secret, sender, generation);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce: Nonce = nonce.into();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|err| Error::generic(format!("treekem application seal failed: {err}")))?;
    Ok(AppCiphertext {
        epoch,
        sender,
        generation,
        ciphertext,
    })
}

/// Open an [`AppCiphertext`] with the recipient's view of `encryption_secret`.
pub(crate) fn open(encryption_secret: &Secret, message: &AppCiphertext) -> Result<Vec<u8>, Error> {
    let (key, nonce) = message_key_nonce(encryption_secret, message.sender, message.generation);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce: Nonce = nonce.into();
    cipher
        .decrypt(&nonce, message.ciphertext.as_ref())
        .map_err(|err| Error::generic(format!("treekem application open failed: {err}")))
}
