//! Crypto helpers for the ratchet tree: HPKE-style seal/open (ML-KEM + ChaCha20-Poly1305), node-key
//! derivation from path secrets, and the key-schedule KDFs. All post-quantum (ML-KEM + SHA3/BLAKE3).

use crate::tree::math::NodeIndex;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use citadel_types::crypto::{AlgorithmsExt, KemAlgorithm};
use citadel_types::errors::Error;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Length of a path/node/epoch secret.
pub const SECRET_LEN: usize = 32;
/// A 32-byte secret (path secret, node secret, epoch-schedule secret).
pub type Secret = [u8; SECRET_LEN];

/// Path secrets by node. Every secret is wiped when the map is dropped, including when it is
/// replaced by a newer one.
#[derive(Clone, Default)]
pub struct SecretMap(HashMap<NodeIndex, Secret>);

impl Deref for SecretMap {
    type Target = HashMap<NodeIndex, Secret>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SecretMap {
    fn drop(&mut self) {
        for secret in self.0.values_mut() {
            secret.zeroize();
        }
    }
}

/// Derive the next path secret moving one step toward the root.
pub fn derive_path_secret(ps: &Secret) -> Secret {
    *blake3::keyed_hash(ps, b"citadel-treekem-path-secret-v1").as_bytes()
}

/// Derive a node's "node secret" (the seed source for its KEM keypair) from its path secret.
pub fn derive_node_secret(ps: &Secret) -> Secret {
    *blake3::keyed_hash(ps, b"citadel-treekem-node-secret-v1").as_bytes()
}

/// The one suite a tree's keys are on: ML-KEM-1024.
pub const CURRENT_SUITE: KemAlgorithm = KemAlgorithm::MlKem1024Fips203;

/// The suite of a tree node's public key, which must be [`CURRENT_SUITE`]. A key of any other
/// length is refused, naming the KEM it is a key of where it is one.
pub fn suite_of(public_key: &[u8]) -> Result<KemAlgorithm, Error> {
    require_tree_suite(
        public_key,
        citadel_pqcrypto::kem_key_check::public_key_len,
        "public key",
    )
}

/// The suite a KEM ciphertext was sealed under, which must be [`CURRENT_SUITE`], refused as
/// [`suite_of`] refuses a key.
pub fn suite_of_ciphertext(kem_ct: &[u8]) -> Result<KemAlgorithm, Error> {
    require_tree_suite(
        kem_ct,
        citadel_pqcrypto::kem_key_check::ciphertext_len,
        "ciphertext",
    )
}

fn require_tree_suite(
    bytes: &[u8],
    len_of: fn(KemAlgorithm) -> usize,
    what: &str,
) -> Result<KemAlgorithm, Error> {
    if len_of(CURRENT_SUITE) == bytes.len() {
        return Ok(CURRENT_SUITE);
    }
    let named = KemAlgorithm::list()
        .into_iter()
        .find(|suite| len_of(*suite) == bytes.len());
    Err(Error::generic(match named {
        Some(other) => format!(
            "treekem: a {other:?} KEM {what} is refused; a tree runs only on {CURRENT_SUITE:?}"
        ),
        None => format!(
            "treekem: a {}-byte KEM {what} is of no KEM; a tree runs only on {CURRENT_SUITE:?}",
            bytes.len()
        ),
    }))
}

/// 64-byte keygen seed (`d || z`) for a node, from its node secret.
fn node_kem_seed(node_secret: &Secret) -> [u8; 64] {
    use sha3::{Digest, Sha3_512};
    let out = Sha3_512::new()
        .chain_update(node_secret)
        .chain_update(b"citadel-treekem-kem-seed-ml-kem-1024-v1")
        .finalize();
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&out);
    seed
}

/// Deterministically derive a node's keypair `(public, secret)` from its path secret. Any member
/// who learns the path secret recomputes the identical keypair.
pub fn node_keypair_from_path_secret(ps: &Secret) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let seed = node_kem_seed(&derive_node_secret(ps));
    citadel_pqcrypto::kem_keypair_from_seed(CURRENT_SUITE, &seed)
}

/// HPKE-seal: encapsulate to `recipient_pk`, a key of the tree's suite, and AEAD-encrypt
/// `plaintext` under the KEM shared secret. Returns `(kem_ciphertext, aead_ciphertext)`.
pub fn hpke_seal(recipient_pk: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (kem_ct, ss) = citadel_pqcrypto::kem_encapsulate(suite_of(recipient_pk)?, recipient_pk)?;
    let aead_ct = aead_seal(&ss, plaintext)?;
    Ok((kem_ct, aead_ct))
}

/// HPKE-open: decapsulate `kem_ct`, a ciphertext of the tree's suite, with `recipient_sk` and
/// AEAD-decrypt `aead_ct`.
pub fn hpke_open(kem_ct: &[u8], aead_ct: &[u8], recipient_sk: &[u8]) -> Result<Vec<u8>, Error> {
    let ss = citadel_pqcrypto::kem_decapsulate(suite_of_ciphertext(kem_ct)?, kem_ct, recipient_sk)?;
    aead_open(&ss, aead_ct)
}

/// Opens what was sealed to a node whose path secret is `ps`, deriving the node's secret key.
pub fn hpke_open_with_path_secret(
    ps: &Secret,
    kem_ct: &[u8],
    aead_ct: &[u8],
) -> Result<Vec<u8>, Error> {
    let (_pk, sk) = node_keypair_from_path_secret(ps)?;
    hpke_open(kem_ct, aead_ct, &sk)
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
        assert_eq!(suite_of(&pk1).unwrap(), CURRENT_SUITE);

        let secret = b"a 32-byte path secret to deliver".to_vec();
        let (kem_ct, aead_ct) = hpke_seal(&pk1, &secret).unwrap();
        let got = hpke_open(&kem_ct, &aead_ct, &sk1).unwrap();
        assert_eq!(got, secret, "HPKE seal->open must round-trip");
        assert_eq!(
            hpke_open_with_path_secret(&ps, &kem_ct, &aead_ct).unwrap(),
            secret
        );

        // wrong key fails to open
        let (_pk_other, sk_other) = node_keypair_from_path_secret(&[1u8; 32]).unwrap();
        assert!(hpke_open(&kem_ct, &aead_ct, &sk_other).is_err());
    }

    #[test]
    fn a_key_of_no_tree_suite_is_refused() {
        assert!(suite_of(&[0u8; 1000]).is_err());
        assert!(hpke_seal(&[0u8; 1000], b"x").is_err());
    }

    /// A key or ciphertext of a KEM other than the tree's is refused, naming that KEM.
    #[test]
    fn a_key_of_another_kem_is_refused_by_name() {
        let other = KemAlgorithm::MlKem768Fips203;
        let (pk, _sk) = citadel_pqcrypto::kem_keypair_from_seed(other, &[3u8; 64]).unwrap();
        let refusal = suite_of(&pk).unwrap_err().to_string();
        assert!(
            refusal.contains(
                "a MlKem768Fips203 KEM public key is refused; a tree runs only on MlKem1024Fips203"
            ),
            "{refusal}"
        );
        assert!(hpke_seal(&pk, b"x").is_err());

        let (ct, _ss) = citadel_pqcrypto::kem_encapsulate(other, &pk).unwrap();
        let refusal = suite_of_ciphertext(&ct).unwrap_err().to_string();
        assert!(
            refusal.contains(
                "a MlKem768Fips203 KEM ciphertext is refused; a tree runs only on MlKem1024Fips203"
            ),
            "{refusal}"
        );
        assert!(hpke_open_with_path_secret(&[3u8; 32], &ct, &[0u8; 32]).is_err());
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
