//! Application messages: per-epoch, per-sender, per-message AEAD keyed off the group `encryption_secret`.
//!
//! Every member can derive *any* sender's message key for a given generation from the shared epoch
//! `encryption_secret` (an MLS "secret-tree"-style derivation), so a sender just tags each ciphertext
//! with `(sender, generation)` and recipients derive the matching key. Per-message keys give forward
//! secrecy within an epoch (a used generation's key can be dropped); the relay sees only ciphertext.
//!
//! Because every member can derive every message key, a ciphertext proves nothing about who sealed
//! it. Each one is therefore signed by its sender's leaf key ([`crate::signing`]), and a recipient
//! opens it only once that signature verifies under the leaf it names.

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
    /// The sender state's incarnation: drawn afresh each time a stored state is loaded, so a
    /// generation sent before a restart is never sealed again under the same key.
    pub incarnation: u64,
    /// Per-sender message counter (the "generation").
    pub generation: u32,
    /// AEAD ciphertext (ChaCha20-Poly1305).
    pub ciphertext: Vec<u8>,
    /// The sender leaf's ML-DSA-65 signature over `(epoch, sender, incarnation, generation,
    /// ciphertext)`.
    pub signature: Vec<u8>,
}

/// The message key + nonce for `(sender, generation)` under `encryption_secret`. Deterministic for all
/// members, so any recipient derives the sender's key.
fn message_key_nonce(
    encryption_secret: &Secret,
    sender: u32,
    incarnation: u64,
    generation: u32,
) -> ([u8; 32], [u8; 12]) {
    let mut hasher = blake3::Hasher::new_derive_key("citadel-treekem-app-message-v2");
    hasher.update(encryption_secret);
    hasher.update(&sender.to_be_bytes());
    hasher.update(&incarnation.to_be_bytes());
    hasher.update(&generation.to_be_bytes());
    let mut out = [0u8; 44];
    hasher.finalize_xof().fill(&mut out);
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out[32..44]);
    (key, nonce)
}

/// Seal `plaintext` under the `(sender, generation)` message key and sign it with the sender's leaf
/// key.
pub(crate) fn seal(
    encryption_secret: &Secret,
    signing_key: &crate::signing::LeafSigningKey,
    epoch: u64,
    sender: u32,
    incarnation: u64,
    generation: u32,
    plaintext: &[u8],
) -> Result<AppCiphertext, Error> {
    let (key, nonce) = message_key_nonce(encryption_secret, sender, incarnation, generation);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce: Nonce = nonce.into();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|err| Error::generic(format!("treekem application seal failed: {err}")))?;
    let frame = crate::signing::FrameId {
        epoch,
        sender,
        incarnation,
        generation,
    };
    let signature = crate::signing::sign_frame(signing_key, frame, &ciphertext)?;
    Ok(AppCiphertext {
        epoch,
        sender,
        incarnation,
        generation,
        ciphertext,
        signature,
    })
}

/// Open an [`AppCiphertext`] with the recipient's view of `encryption_secret`. The caller has
/// verified its signature.
pub(crate) fn open(encryption_secret: &Secret, message: &AppCiphertext) -> Result<Vec<u8>, Error> {
    let (key, nonce) = message_key_nonce(
        encryption_secret,
        message.sender,
        message.incarnation,
        message.generation,
    );
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce: Nonce = nonce.into();
    cipher
        .decrypt(&nonce, message.ciphertext.as_ref())
        .map_err(|err| Error::generic(format!("treekem application open failed: {err}")))
}

impl AppCiphertext {
    /// The frame this message is.
    pub fn frame(&self) -> crate::signing::FrameId {
        crate::signing::FrameId {
            epoch: self.epoch,
            sender: self.sender,
            incarnation: self.incarnation,
            generation: self.generation,
        }
    }
}
