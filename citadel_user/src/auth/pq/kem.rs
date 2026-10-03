//! ML-KEM-1024 as a sign-in factor: a keypair the client derives from a 64-byte seed
//! (FIPS 203 `KeyGen_internal(d, z)`), the encapsulation key the server stores, and the
//! encapsulate / decapsulate pair that proves the factor.

use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use citadel_pqcrypto::libcrux_kem;
use citadel_types::crypto::KemAlgorithm;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use zeroize::Zeroizing;

/// Every factor uses this parameter set.
pub const FACTOR_KEM: KemAlgorithm = KemAlgorithm::MlKem1024Fips203;
/// FIPS 203 ML-KEM-1024 encapsulation-key length.
pub const EK_LEN: usize = 1568;
/// FIPS 203 ML-KEM-1024 ciphertext length.
pub const CT_LEN: usize = 1568;
/// The `(d, z)` seed of FIPS 203 `KeyGen_internal`.
pub const SEED_LEN: usize = 64;

fn crypto(err: impl std::fmt::Debug) -> AccountError {
    error!(ErrorCode::PqSignInCrypto, format!("{err:?}"))
}

/// A factor's public key. Constructing one, including by deserializing, runs the FIPS 203
/// encapsulation-key check, so a value of this type is always safe to encapsulate to.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct EncapsulationKey(Vec<u8>);

impl TryFrom<Vec<u8>> for EncapsulationKey {
    type Error = AccountError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() == EK_LEN && libcrux_kem::public_key_is_valid(FACTOR_KEM, &bytes) {
            Ok(Self(bytes))
        } else {
            Err(error!(
                ErrorCode::PqSignInMalformed,
                "an ML-KEM-1024 encapsulation key"
            ))
        }
    }
}

impl From<EncapsulationKey> for Vec<u8> {
    fn from(ek: EncapsulationKey) -> Self {
        ek.0
    }
}

impl EncapsulationKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// A short, public name for this key: what a client sends to say which recovery code it holds
    /// without sending the key itself.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = sha3::Sha3_256::default();
        hasher.update(b"citadel-factor-fingerprint-v1");
        hasher.update(&self.0);
        hasher.finalize().into()
    }
}

impl std::fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fp = self.fingerprint();
        write!(
            f,
            "EncapsulationKey({:02x}{:02x}{:02x}{:02x}…)",
            fp[0], fp[1], fp[2], fp[3]
        )
    }
}

/// An ML-KEM-1024 ciphertext, checked for length when it is built or deserialized.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct KemCiphertext(Vec<u8>);

impl TryFrom<Vec<u8>> for KemCiphertext {
    type Error = AccountError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() == CT_LEN {
            Ok(Self(bytes))
        } else {
            Err(error!(
                ErrorCode::PqSignInMalformed,
                "an ML-KEM-1024 ciphertext"
            ))
        }
    }
}

impl From<KemCiphertext> for Vec<u8> {
    fn from(ct: KemCiphertext) -> Self {
        ct.0
    }
}

impl KemCiphertext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The 32-byte secret one encapsulation shares. It never crosses the wire: the client proves it
/// with a tag, and both sides mix it into the session's key schedule.
pub struct SharedSecret(Zeroizing<[u8; 32]>);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_vec(bytes: Vec<u8>) -> Result<Self, AccountError> {
        let bytes = Zeroizing::new(bytes);
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(crypto)?;
        Ok(Self(Zeroizing::new(array)))
    }
}

/// The seed a factor's keypair is derived from. The client recomputes it at every sign-in and
/// never stores it.
pub struct FactorSeed(Zeroizing<[u8; SEED_LEN]>);

impl FactorSeed {
    pub fn new(seed: [u8; SEED_LEN]) -> Self {
        Self(Zeroizing::new(seed))
    }
}

/// A factor's keypair, rebuilt from its seed on the client.
pub struct FactorKeypair {
    ek: EncapsulationKey,
    dk: Zeroizing<Vec<u8>>,
}

impl FactorKeypair {
    /// FIPS 203 `KeyGen_internal(d, z)` with `d ‖ z` = `seed`: the same seed always gives the
    /// same keypair, which is what lets a password or a key touch stand in for a stored key.
    pub fn derive(seed: &FactorSeed) -> Result<Self, AccountError> {
        let (ek, dk) = libcrux_kem::keypair_from_seed(FACTOR_KEM, &seed.0).map_err(crypto)?;
        Ok(Self {
            ek: EncapsulationKey::try_from(ek)?,
            dk: Zeroizing::new(dk),
        })
    }

    pub fn encapsulation_key(&self) -> &EncapsulationKey {
        &self.ek
    }

    /// ML-KEM decapsulation. A ciphertext that was not made for this key does not fail: FIPS 203
    /// implicit rejection returns an unrelated secret, so the tag built from it will not verify.
    pub fn decapsulate(&self, ct: &KemCiphertext) -> Result<SharedSecret, AccountError> {
        let ss = libcrux_kem::decapsulate(FACTOR_KEM, ct.as_bytes(), &self.dk).map_err(crypto)?;
        SharedSecret::from_vec(ss)
    }
}

/// The server's half of a factor proof: a fresh ciphertext for `ek` and the secret it carries.
pub fn encapsulate(ek: &EncapsulationKey) -> Result<(KemCiphertext, SharedSecret), AccountError> {
    let (ct, ss) = libcrux_kem::encapsulate(FACTOR_KEM, ek.as_bytes()).map_err(crypto)?;
    Ok((KemCiphertext::try_from(ct)?, SharedSecret::from_vec(ss)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_always_gives_the_same_key_and_the_key_decapsulates_its_ciphertext() {
        let a = FactorKeypair::derive(&FactorSeed::new([3u8; SEED_LEN])).unwrap();
        let b = FactorKeypair::derive(&FactorSeed::new([3u8; SEED_LEN])).unwrap();
        assert_eq!(a.encapsulation_key(), b.encapsulation_key());
        let (ct, server) = encapsulate(a.encapsulation_key()).unwrap();
        assert_eq!(b.decapsulate(&ct).unwrap().as_bytes(), server.as_bytes());
    }

    #[test]
    fn another_seed_recovers_an_unrelated_secret() {
        let right = FactorKeypair::derive(&FactorSeed::new([3u8; SEED_LEN])).unwrap();
        let wrong = FactorKeypair::derive(&FactorSeed::new([4u8; SEED_LEN])).unwrap();
        let (ct, server) = encapsulate(right.encapsulation_key()).unwrap();
        assert_ne!(
            wrong.decapsulate(&ct).unwrap().as_bytes(),
            server.as_bytes()
        );
    }

    #[test]
    fn wire_types_refuse_bad_lengths_and_unreduced_keys() {
        assert!(EncapsulationKey::try_from(vec![0u8; EK_LEN - 1]).is_err());
        assert!(EncapsulationKey::try_from(vec![0xFFu8; EK_LEN]).is_err());
        assert!(KemCiphertext::try_from(vec![0u8; CT_LEN + 1]).is_err());
        let kp = FactorKeypair::derive(&FactorSeed::new([9u8; SEED_LEN])).unwrap();
        let bytes = bincode::serialize(kp.encapsulation_key()).unwrap();
        let back: EncapsulationKey = bincode::deserialize(&bytes).unwrap();
        assert_eq!(&back, kp.encapsulation_key());
    }
}
