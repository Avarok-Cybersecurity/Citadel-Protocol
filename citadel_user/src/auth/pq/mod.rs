//! Post-quantum sign-in.
//!
//! Every factor is an ML-KEM-1024 keypair the client derives deterministically from a 64-byte
//! seed, and the server stores only the encapsulation key. To prove a factor the server
//! encapsulates, the client decapsulates and returns
//! `HMAC-SHA3-256(K, "citadel-auth-v1" ‖ factor_id ‖ transcript_hash)`, and the server compares in
//! constant time. Every proven `K` goes into the session key both sides add to the channel's
//! pre-shared keys.
//!
//! | Factor | Seed |
//! |---|---|
//! | Password | `Argon2id(OPRF(k_user, SHA3-256(password)), salt_user)`, on the client |
//! | Security key | HKDF-SHA3 of its WebAuthn PRF output and credential id |
//! | Recovery code | HKDF-SHA3 of the 128-bit code |
//!
//! The server never stretches a password: [`server`] evaluates the OPRF (one ristretto255 scalar
//! multiplication), encapsulates once per challenged factor, and compares tags. Argon2id runs only
//! in [`client`]. No classical signature is created or verified anywhere.

pub mod client;
pub mod kem;
pub mod messages;
pub mod oprf;
pub mod policy;
pub mod proof;
pub mod record;
pub mod recovery;
pub mod seed;
pub mod server;

#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod tests_decoy;
#[cfg(test)]
mod tests_factors;
#[cfg(test)]
mod tests_record;

use messages::{transcript_bytes, LoginChallenge, LoginStart};
use proof::{TranscriptHash, TranscriptPurpose};

/// The transcript a login's tags are bound to: the account, the client's start and the server's
/// challenge, byte for byte.
pub fn login_transcript(
    cid: u64,
    start: &LoginStart,
    challenge: &LoginChallenge,
) -> TranscriptHash {
    TranscriptHash::new(
        TranscriptPurpose::Login,
        cid,
        &[&transcript_bytes(start), &transcript_bytes(challenge)],
    )
}

pub(crate) fn random_32() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}
