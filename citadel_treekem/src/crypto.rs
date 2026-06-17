//! Crypto helpers for the ratchet tree: HPKE-style seal/open (ML-KEM + ChaCha20-Poly1305), node-key
//! derivation from path secrets, and the key-schedule KDFs. All post-quantum (ML-KEM + SHA3/BLAKE3).

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use citadel_types::errors::Error;

/// Length of a path/node/epoch secret.
pub const SECRET_LEN: usize = 32;
/// A 32-byte secret (path secret, node secret, epoch-schedule secret).
pub type Secret = [u8; SECRET_LEN];

/// Derive the next path secret moving one step toward the root.
pub fn derive_path_secret(ps: &Secret) -> Secret {
    *blake3::keyed_hash(ps, b"citadel-treekem-path-secret-v1").as_bytes()
}

/// Derive a node's "node secret" (the seed source for its KEM keypair) from its path secret.
pub fn derive_node_secret(ps: &Secret) -> Secret {
    *blake3::keyed_hash(ps, b"citadel-treekem-node-secret-v1").as_bytes()
}

/// 64-byte ML-KEM keygen seed (`d || z`) for a node, from its node secret.
fn node_kem_seed(node_secret: &Secret) -> [u8; 64] {
    use sha3::{Digest, Sha3_512};
    let out = Sha3_512::new()
        .chain_update(node_secret)
        .chain_update(b"citadel-treekem-kem-seed-v1")
        .finalize();
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&out);
    seed
}

/// Deterministically derive a node's ML-KEM keypair `(public, secret)` from its path secret. Any member
/// who learns the path secret recomputes the identical keypair.
pub fn node_keypair_from_path_secret(ps: &Secret) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let seed = node_kem_seed(&derive_node_secret(ps));
    citadel_pqcrypto::kem_keypair_from_seed(&seed)
}

/// HPKE-seal: encapsulate to `recipient_pk` and AEAD-encrypt `plaintext` under the KEM shared secret.
/// Returns `(kem_ciphertext, aead_ciphertext)`.
pub fn hpke_seal(recipient_pk: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (kem_ct, ss) = citadel_pqcrypto::kem_encapsulate(recipient_pk)?;
    let aead_ct = aead_seal(&ss, plaintext)?;
    Ok((kem_ct, aead_ct))
}

/// HPKE-open: decapsulate `kem_ct` with `recipient_sk` and AEAD-decrypt `aead_ct`.
pub fn hpke_open(kem_ct: &[u8], aead_ct: &[u8], recipient_sk: &[u8]) -> Result<Vec<u8>, Error> {
    let ss = citadel_pqcrypto::kem_decapsulate(kem_ct, recipient_sk)?;
    aead_open(&ss, aead_ct)
}

/// Derive the AEAD key + nonce from a one-shot KEM shared secret. The shared secret is fresh per HPKE
/// seal (a new encapsulation each time), so a deterministic per-secret nonce is safe (key is single-use).
fn aead_key_nonce(ss: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let key = blake3::derive_key("citadel-treekem-hpke-key-v1", ss);
    let nonce_full = blake3::derive_key("citadel-treekem-hpke-nonce-v1", ss);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    (key, nonce)
}

fn aead_seal(ss: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let (key, nonce) = aead_key_nonce(ss);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce: Nonce = nonce.into();
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|err| Error::generic(format!("treekem HPKE seal failed: {err}")))
}

fn aead_open(ss: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let (key, nonce) = aead_key_nonce(ss);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce: Nonce = nonce.into();
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|err| Error::generic(format!("treekem HPKE open failed: {err}")))
}

/// AEAD-seal with an explicit key + 12-byte nonce. The caller must ensure each `(key, nonce)` pair is
/// used at most once (e.g. a single-use content key with a fixed nonce, or a reused key with a
/// per-message nonce derived from unique material).
pub(crate) fn sym_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce: Nonce = (*nonce).into();
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|err| Error::generic(format!("treekem symmetric seal failed: {err}")))
}

/// AEAD-open the counterpart of [`sym_seal`].
pub(crate) fn sym_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce: Nonce = (*nonce).into();
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|err| Error::generic(format!("treekem symmetric open failed: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_keypair_deterministic_and_hpke_roundtrips() {
        let ps: Secret = [9u8; 32];
        let (pk1, sk1) = node_keypair_from_path_secret(&ps).unwrap();
        let (pk2, _sk2) = node_keypair_from_path_secret(&ps).unwrap();
        assert_eq!(pk1, pk2, "same path secret -> same node keypair");

        let secret = b"a 32-byte path secret to deliver".to_vec();
        let (kem_ct, aead_ct) = hpke_seal(&pk1, &secret).unwrap();
        let got = hpke_open(&kem_ct, &aead_ct, &sk1).unwrap();
        assert_eq!(got, secret, "HPKE seal->open must round-trip");

        // wrong key fails to open
        let (_pk_other, sk_other) = node_keypair_from_path_secret(&[1u8; 32]).unwrap();
        assert!(hpke_open(&kem_ct, &aead_ct, &sk_other).is_err());
    }

    #[test]
    fn path_secret_chain_is_one_way_and_distinct() {
        let ps0: Secret = [3u8; 32];
        let ps1 = derive_path_secret(&ps0);
        let ps2 = derive_path_secret(&ps1);
        assert_ne!(ps0, ps1);
        assert_ne!(ps1, ps2);
        assert_ne!(derive_node_secret(&ps0), ps0);
    }
}
