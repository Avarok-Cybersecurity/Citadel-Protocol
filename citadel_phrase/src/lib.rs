//! The recovery phrase: 24 words of the BIP-39 English list encoding a 32-byte seed and an 8-bit
//! SHA3 check (see [`phrase_encode`]). The SDK's account recovery and the agent's portable
//! identity read and write phrases with this one codec and this one word list.

#![forbid(unsafe_code)]

mod phrase;
mod wordlist;

pub use phrase::{
    match_phrase, phrase_decode, phrase_encode, PhraseError, MATCH_PHRASE_DOMAIN, PHRASE_WORDS,
};
pub use wordlist::WORDS;

/// `SHA3-256(part₀ ‖ part₁ ‖ …)`.
pub(crate) fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}
