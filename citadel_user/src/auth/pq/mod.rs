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

pub mod admission;
mod challenge;
pub mod client;
pub mod kem;
pub mod messages;
pub mod oprf;
pub mod phrase;
pub mod policy;
pub mod proof;
pub mod record;
pub mod recovery;
pub mod seed;
pub mod server;
pub mod throttle;

#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod tests_admission;
#[cfg(test)]
mod tests_challenge;
#[cfg(test)]
mod tests_decoy;
#[cfg(test)]
mod tests_factors;
#[cfg(test)]
mod tests_manage;
#[cfg(test)]
mod tests_password_whitespace;
#[cfg(test)]
mod tests_record;
#[cfg(test)]
mod tests_recovery;
#[cfg(test)]
mod tests_recovery_lane;
#[cfg(test)]
mod tests_recovery_manage;
#[cfg(test)]
mod tests_recovery_register;
#[cfg(test)]
mod tests_throttle;

use messages::{
    transcript_bytes, AuthChallenge, LoginStart, ManagementBegin, ManagementChallenge, RecoverStart,
};
use proof::{TranscriptHash, TranscriptPurpose};
use sha3::{Digest, Sha3_256};

/// The transcript a login's tags are bound to: the account, the client's start and the server's
/// challenge, byte for byte as sent.
pub fn login_transcript(cid: u64, start: &LoginStart, challenge: &AuthChallenge) -> TranscriptHash {
    TranscriptHash::new(
        TranscriptPurpose::Login,
        cid,
        &[&transcript_bytes(start), &transcript_bytes(challenge)],
    )
}

/// The transcript a management step-up is bound to: the change asked for, the server's challenge,
/// and the key being added (`ManagementCommit::key_binding`), so a proof made for one change
/// cannot authorize another.
pub fn management_transcript(
    cid: u64,
    begin: &ManagementBegin,
    challenge: &ManagementChallenge,
    key_binding: &[u8],
) -> TranscriptHash {
    TranscriptHash::new(
        TranscriptPurpose::StepUp,
        cid,
        &[
            &transcript_bytes(begin),
            &transcript_bytes(challenge),
            key_binding,
        ],
    )
}

const CHANNEL_BINDING_LABEL: &[u8] = b"citadel-recover-channel-binding-v1";

/// What ties a recovery to the key exchange it rides in: the hash of that exchange's two
/// transfers, as each side sent or received them. A party relaying between two exchanges of its
/// own sees different transfers on each side, so a proof it relays fails, and the ratchet the
/// server installs is always the one the prover's device holds.
pub fn channel_binding(alice_transfer: &[u8], bob_transfer: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::default();
    hasher.update(CHANNEL_BINDING_LABEL);
    for part in [alice_transfer, bob_transfer] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The transcript a recovery's tag is bound to: the key exchange it rides in, the start (with the
/// device it names) and the challenge, so a proof fits one exchange, one device and one challenge.
pub fn recover_transcript(
    cid: u64,
    channel_binding: &[u8; 32],
    start: &RecoverStart,
    challenge: &AuthChallenge,
) -> TranscriptHash {
    TranscriptHash::new(
        TranscriptPurpose::Recover,
        cid,
        &[
            channel_binding,
            &transcript_bytes(start),
            &transcript_bytes(challenge),
        ],
    )
}

pub(crate) fn random_32() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}
