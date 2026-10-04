//! The password factor's hardening layer: an RFC 9497 OPRF (ristretto255 / SHA-512, base mode).
//!
//! The client blinds `SHA3-256(password)`, the server multiplies it by a per-user key, and the
//! client unblinds the result into `rwd`. Only `rwd` reaches Argon2id, so an offline guess
//! against a stolen account record also needs the server's OPRF seed. The OPRF carries none of the
//! post-quantum security; ML-KEM does.
//!
//! The per-user key is derived from the tenant's seed and the username alone, so the server
//! evaluates an unknown username exactly as it evaluates a real one.

use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use hkdf::Hkdf;
use rand::RngCore;
use sha3::Sha3_256;
use voprf::{BlindedElement, EvaluationElement, OprfClient, OprfServer, Ristretto255};
use zeroize::Zeroizing;

const PER_USER_KEY_SALT: &[u8] = b"citadel-oprf-user-key-v1";
const DERIVE_KEY_INFO: &[u8] = b"citadel-oprf-v1";

/// Length of `rwd`, the OPRF output (SHA-512).
pub const RWD_LEN: usize = 64;

fn malformed(what: &'static str) -> AccountError {
    error!(ErrorCode::PqSignInMalformed, what)
}

/// The tenant's OPRF secret. Generated once at provisioning and kept apart from the account rows
/// (on the Durable Object, in its key-value storage), so a copy of the rows alone cannot drive an
/// offline guess. It is never logged.
#[derive(Clone)]
pub struct OprfSeed(Zeroizing<[u8; 32]>);

impl OprfSeed {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A fresh seed, for provisioning.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    /// HKDF-SHA3-256 of the seed for one purpose and one username. Also how the decoys for an
    /// unknown username are made, so they are as stable as a real account's values.
    pub(crate) fn derive<const N: usize>(&self, salt: &[u8], username: &str) -> Zeroizing<[u8; N]> {
        let mut out = Zeroizing::new([0u8; N]);
        Hkdf::<Sha3_256>::new(Some(salt), self.0.as_ref())
            .expand(username.as_bytes(), out.as_mut())
            .expect("the derived lengths used here are valid HKDF-SHA3-256 outputs");
        out
    }
}

impl std::fmt::Debug for OprfSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OprfSeed(***)")
    }
}

/// The server's step: evaluate the client's blinded element under `username`'s key. One
/// ristretto255 scalar multiplication.
pub fn server_evaluate(
    seed: &OprfSeed,
    username: &str,
    blinded: &[u8],
) -> Result<Vec<u8>, AccountError> {
    let user_key = seed.derive::<32>(PER_USER_KEY_SALT, username);
    let server = OprfServer::<Ristretto255>::new_from_seed(user_key.as_ref(), DERIVE_KEY_INFO)
        .map_err(|_| error!(ErrorCode::PqSignInCrypto, "OPRF key derivation"))?;
    let blinded = BlindedElement::<Ristretto255>::deserialize(blinded)
        .map_err(|_| malformed("an OPRF blinded element"))?;
    Ok(server.blind_evaluate(&blinded).serialize().to_vec())
}

/// The client's blinding state between sending the blinded element and unblinding the reply.
pub struct OprfClientState(OprfClient<Ristretto255>);

/// The client's first step. `input` is `SHA3-256(password)`.
pub fn client_blind(input: &[u8]) -> Result<(OprfClientState, Vec<u8>), AccountError> {
    let blind = OprfClient::<Ristretto255>::blind(input, &mut rand::thread_rng())
        .map_err(|_| malformed("an OPRF input"))?;
    Ok((
        OprfClientState(blind.state),
        blind.message.serialize().to_vec(),
    ))
}

impl OprfClientState {
    /// Unblind the server's evaluation into `rwd`. An evaluation that is not a valid group element
    /// is refused here; a valid but wrong one gives a wrong `rwd`, and so a proof that will not
    /// verify.
    pub fn finalize(
        &self,
        input: &[u8],
        evaluated: &[u8],
    ) -> Result<Zeroizing<[u8; RWD_LEN]>, AccountError> {
        let evaluated = EvaluationElement::<Ristretto255>::deserialize(evaluated)
            .map_err(|_| malformed("an OPRF evaluation"))?;
        let output = self
            .0
            .finalize(input, &evaluated)
            .map_err(|_| error!(ErrorCode::PqSignInCrypto, "OPRF finalization"))?;
        let mut rwd = Zeroizing::new([0u8; RWD_LEN]);
        rwd.copy_from_slice(output.as_slice());
        Ok(rwd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(seed: &OprfSeed, user: &str, input: &[u8]) -> Zeroizing<[u8; RWD_LEN]> {
        let (state, blinded) = client_blind(input).unwrap();
        let evaluated = server_evaluate(seed, user, &blinded).unwrap();
        state.finalize(input, &evaluated).unwrap()
    }

    #[test]
    fn the_output_is_stable_and_depends_on_input_user_and_seed() {
        let seed = OprfSeed::from_bytes([5u8; 32]);
        let rwd = run(&seed, "alice", b"pw-digest");
        assert_eq!(
            *rwd,
            *run(&seed, "alice", b"pw-digest"),
            "blinding must cancel out"
        );
        assert_ne!(*rwd, *run(&seed, "alice", b"other-digest"));
        assert_ne!(*rwd, *run(&seed, "bob", b"pw-digest"));
        assert_ne!(
            *rwd,
            *run(&OprfSeed::from_bytes([6u8; 32]), "alice", b"pw-digest")
        );
    }

    #[test]
    fn a_tampered_evaluation_changes_rwd_or_is_refused() {
        let seed = OprfSeed::from_bytes([5u8; 32]);
        let (state, blinded) = client_blind(b"pw-digest").unwrap();
        let good = server_evaluate(&seed, "alice", &blinded).unwrap();
        let honest = state.finalize(b"pw-digest", &good).unwrap();
        // A different valid element: the evaluation under another user's key.
        let other = server_evaluate(&seed, "mallory", &blinded).unwrap();
        assert_ne!(*honest, *state.finalize(b"pw-digest", &other).unwrap());
        let mut garbage = good.clone();
        garbage[31] ^= 0xFF;
        assert!(state.finalize(b"pw-digest", &garbage).is_err());
    }

    #[test]
    fn a_malformed_blinded_element_is_refused() {
        let seed = OprfSeed::from_bytes([5u8; 32]);
        assert!(server_evaluate(&seed, "alice", &[0xFFu8; 32]).is_err());
        assert!(server_evaluate(&seed, "alice", &[1u8; 5]).is_err());
    }
}
