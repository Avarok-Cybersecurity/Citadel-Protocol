//! Crypto helpers for the ratchet tree: HPKE-style seal/open (ML-KEM + ChaCha20-Poly1305), node-key
//! derivation from path secrets, and the key-schedule KDFs. All post-quantum (ML-KEM + SHA3/BLAKE3).

use crate::tree::math::NodeIndex;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use citadel_types::crypto::KemAlgorithm;
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

/// The suite of a tree node's key that every node before 0.12.4 derives and opens.
pub const ROUND_3_SUITE: KemAlgorithm = KemAlgorithm::MlKem;
/// The suite of a tree node's key when every member who must open it can: ML-KEM-1024.
pub const CURRENT_SUITE: KemAlgorithm = KemAlgorithm::MlKem1024Fips203;

/// The suite of a tree node's public key, told by its length. A tree holds only the two suites
/// above, whose keys differ in length.
pub fn suite_of(public_key: &[u8]) -> Result<KemAlgorithm, Error> {
    suite_by_len(
        public_key,
        citadel_pqcrypto::kem_key_check::public_key_len,
        "public key",
    )
}

/// The suite a KEM ciphertext was sealed under, told by its length as [`suite_of`] tells a key's.
pub fn suite_of_ciphertext(kem_ct: &[u8]) -> Result<KemAlgorithm, Error> {
    suite_by_len(
        kem_ct,
        citadel_pqcrypto::kem_key_check::ciphertext_len,
        "ciphertext",
    )
}

fn suite_by_len(
    bytes: &[u8],
    len_of: fn(KemAlgorithm) -> usize,
    what: &str,
) -> Result<KemAlgorithm, Error> {
    [ROUND_3_SUITE, CURRENT_SUITE]
        .into_iter()
        .find(|suite| len_of(*suite) == bytes.len())
        .ok_or_else(|| {
            Error::generic(format!(
                "treekem: a {}-byte KEM {what} is of no suite a tree uses",
                bytes.len()
            ))
        })
}

/// 64-byte keygen seed (`d || z`) for a node of `suite`, from its node secret. The round-3 label is
/// the one every earlier release uses, so both derive the same round-3 key from a path secret.
fn node_kem_seed(suite: KemAlgorithm, node_secret: &Secret) -> [u8; 64] {
    use sha3::{Digest, Sha3_512};
    let label: &[u8] = if suite == ROUND_3_SUITE {
        b"citadel-treekem-kem-seed-v1"
    } else {
        b"citadel-treekem-kem-seed-ml-kem-1024-v1"
    };
    let out = Sha3_512::new()
        .chain_update(node_secret)
        .chain_update(label)
        .finalize();
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&out);
    seed
}

/// Deterministically derive a node's keypair `(public, secret)` of `suite` from its path secret.
/// Any member who learns the path secret recomputes the identical keypair.
pub fn node_keypair_from_path_secret(
    suite: KemAlgorithm,
    ps: &Secret,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let seed = node_kem_seed(suite, &derive_node_secret(ps));
    citadel_pqcrypto::kem_keypair_from_seed(suite, &seed)
}

/// HPKE-seal: encapsulate to `recipient_pk`, in the suite its length names, and AEAD-encrypt
/// `plaintext` under the KEM shared secret. Returns `(kem_ciphertext, aead_ciphertext)`.
pub fn hpke_seal(recipient_pk: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (kem_ct, ss) = citadel_pqcrypto::kem_encapsulate(suite_of(recipient_pk)?, recipient_pk)?;
    let aead_ct = aead_seal(&ss, plaintext)?;
    Ok((kem_ct, aead_ct))
}

/// HPKE-open: decapsulate `kem_ct` with `recipient_sk` of `suite` and AEAD-decrypt `aead_ct`.
pub fn hpke_open(
    suite: KemAlgorithm,
    kem_ct: &[u8],
    aead_ct: &[u8],
    recipient_sk: &[u8],
) -> Result<Vec<u8>, Error> {
    let ss = citadel_pqcrypto::kem_decapsulate(suite, kem_ct, recipient_sk)?;
    aead_open(&ss, aead_ct)
}

/// Opens what was sealed to a node whose path secret is `ps`, deriving the node's secret key in the
/// suite the ciphertext was sealed under.
pub fn hpke_open_with_path_secret(
    ps: &Secret,
    kem_ct: &[u8],
    aead_ct: &[u8],
) -> Result<Vec<u8>, Error> {
    let suite = suite_of_ciphertext(kem_ct)?;
    let (_pk, sk) = node_keypair_from_path_secret(suite, ps)?;
    hpke_open(suite, kem_ct, aead_ct, &sk)
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
        for suite in [ROUND_3_SUITE, CURRENT_SUITE] {
            let ps: Secret = [9u8; 32];
            let (pk1, sk1) = node_keypair_from_path_secret(suite, &ps).unwrap();
            let (pk2, _sk2) = node_keypair_from_path_secret(suite, &ps).unwrap();
            assert_eq!(pk1, pk2, "same path secret -> same node keypair");
            assert_eq!(suite_of(&pk1).unwrap(), suite);

            let secret = b"a 32-byte path secret to deliver".to_vec();
            let (kem_ct, aead_ct) = hpke_seal(&pk1, &secret).unwrap();
            let got = hpke_open(suite, &kem_ct, &aead_ct, &sk1).unwrap();
            assert_eq!(got, secret, "HPKE seal->open must round-trip");
            assert_eq!(
                hpke_open_with_path_secret(&ps, &kem_ct, &aead_ct).unwrap(),
                secret
            );

            // wrong key fails to open
            let (_pk_other, sk_other) = node_keypair_from_path_secret(suite, &[1u8; 32]).unwrap();
            assert!(hpke_open(suite, &kem_ct, &aead_ct, &sk_other).is_err());
        }
    }

    /// A round-3 node key is the one every earlier release derives from the same path secret.
    #[test]
    fn round_3_node_keys_match_earlier_releases() {
        use sha3::{Digest, Sha3_512};
        let ps: Secret = [5u8; 32];
        let out = Sha3_512::new()
            .chain_update(derive_node_secret(&ps))
            .chain_update(b"citadel-treekem-kem-seed-v1")
            .finalize();
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&out);
        let earlier = citadel_pqcrypto::kem_keypair_from_seed(KemAlgorithm::MlKem, &seed).unwrap();
        assert_eq!(
            node_keypair_from_path_secret(ROUND_3_SUITE, &ps).unwrap(),
            earlier
        );
    }

    #[test]
    fn a_key_of_no_tree_suite_is_refused() {
        assert!(suite_of(&[0u8; 1000]).is_err());
        assert!(hpke_seal(&[0u8; 1000], b"x").is_err());
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
