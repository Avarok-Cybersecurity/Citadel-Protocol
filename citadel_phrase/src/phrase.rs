//! The recovery phrase: 24 words of the BIP-39 English list encoding the
//! 32-byte seed and an 8-bit SHA3 check, eleven bits per word, most significant first:
//!
//! ```text
//! bits  = seed[32] ‖ SHA3-256(seed)[0]          -- 264 bits
//! words = WORDS[bits[11i .. 11i+11]] for i in 0..24
//! ```
//!
//! The layout is BIP-39's with SHA3-256 in place of SHA-256, so a BIP-39 wallet will not accept
//! this phrase as its own (its check byte differs with probability 255/256), and vice versa.

use crate::sha3_256;
use crate::wordlist::WORDS;
use std::fmt;
use zeroize::Zeroizing;

pub const PHRASE_WORDS: usize = 24;
/// Domain of the "Sign in with Citadel" match-phrase hash.
pub const MATCH_PHRASE_DOMAIN: &[u8] = b"citadel-sign-in-match-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhraseError {
    WordCount(usize),
    /// The word at this position (0-based) is not in the list.
    UnknownWord(usize),
    /// Every word is known and the check does not match: a word is wrong or out of order.
    Checksum,
}

impl fmt::Display for PhraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WordCount(n) => write!(f, "a recovery phrase is {PHRASE_WORDS} words, not {n}"),
            Self::UnknownWord(at) => write!(f, "word {} is not a recovery-phrase word", at + 1),
            Self::Checksum => write!(f, "the recovery phrase's check does not match"),
        }
    }
}

impl std::error::Error for PhraseError {}

pub fn phrase_encode(seed: &[u8; 32]) -> [&'static str; PHRASE_WORDS] {
    let mut bits = Zeroizing::new([0u8; 33]);
    bits[..32].copy_from_slice(seed);
    bits[32] = sha3_256(&[seed])[0];
    let mut words = [""; PHRASE_WORDS];
    for (i, word) in words.iter_mut().enumerate() {
        *word = WORDS[read_11(&bits[..], i * 11)];
    }
    words
}

/// The seed a phrase encodes. Words must be exactly as `phrase_encode` gives them (lowercase,
/// no surrounding space); normalising typed input is the caller's.
pub fn phrase_decode(words: &[&str]) -> Result<[u8; 32], PhraseError> {
    if words.len() != PHRASE_WORDS {
        return Err(PhraseError::WordCount(words.len()));
    }
    let mut bits = Zeroizing::new([0u8; 33]);
    for (i, word) in words.iter().enumerate() {
        let index = WORDS
            .binary_search(word)
            .map_err(|_| PhraseError::UnknownWord(i))?;
        write_11(&mut bits[..], i * 11, index);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bits[..32]);
    if sha3_256(&[&seed])[0] != bits[32] {
        return Err(PhraseError::Checksum);
    }
    Ok(seed)
}

/// The three words a sign-in link's `challenge` shows on both ends:
/// the first 33 bits of `SHA3-256("citadel-sign-in-match-v1" ‖ 0x00 ‖ challenge)`, as three
/// 11-bit indices into the recovery-phrase list. A page forwarding another challenge shows
/// other words.
pub fn match_phrase(challenge: &[u8; 32]) -> [&'static str; 3] {
    let h = sha3_256(&[MATCH_PHRASE_DOMAIN, &[0], challenge]);
    [0, 1, 2].map(|i| WORDS[read_11(&h, i * 11)])
}

fn read_11(bits: &[u8], at: usize) -> usize {
    (0..11).fold(0usize, |acc, k| {
        let bit = at + k;
        (acc << 1) | usize::from((bits[bit / 8] >> (7 - bit % 8)) & 1)
    })
}

fn write_11(bits: &mut [u8], at: usize, value: usize) {
    for k in 0..11 {
        if (value >> (10 - k)) & 1 == 1 {
            let bit = at + k;
            bits[bit / 8] |= 1 << (7 - bit % 8);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Control: drop the check-byte comparison in `phrase_decode` → a phrase with two words
    //! swapped decodes, and `a_wrong_word_order_or_count_is_refused` goes red.
    use super::*;

    #[test]
    fn the_word_list_is_bip39_english_and_sorted() {
        let joined: String = WORDS.iter().map(|w| format!("{w}\n")).collect();
        assert_eq!(
            sha256::digest(joined.as_bytes()),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert!(WORDS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn a_phrase_round_trips_and_its_last_word_carries_the_sha3_check() {
        for seed in [[0u8; 32], [0xff; 32], core::array::from_fn(|i| i as u8)] {
            let words = phrase_encode(&seed);
            assert_eq!(phrase_decode(&words), Ok(seed));
        }
        let zero = phrase_encode(&[0; 32]);
        assert!(zero[..23].iter().all(|w| *w == "abandon"));
        // The last 11 bits are the seed's last 3 bits (zero) and the check byte.
        assert_eq!(zero[23], WORDS[usize::from(sha3_256(&[&[0u8; 32]])[0])]);
        // BIP-39 (SHA-256) would end in "art"; this list's check is SHA3.
        assert_ne!(zero[23], "art");
    }

    #[test]
    fn a_wrong_word_order_or_count_is_refused() {
        let seed: [u8; 32] = core::array::from_fn(|i| (i * 7) as u8);
        let words = phrase_encode(&seed);
        assert_eq!(phrase_decode(&words[..23]), Err(PhraseError::WordCount(23)));
        let mut unknown = words;
        unknown[5] = "citadel";
        assert_eq!(phrase_decode(&unknown), Err(PhraseError::UnknownWord(5)));
        let mut upper = words;
        let shout = words[0].to_uppercase();
        upper[0] = &shout;
        assert_eq!(phrase_decode(&upper), Err(PhraseError::UnknownWord(0)));
        let mut swapped = words;
        swapped.swap(0, 1);
        assert_ne!(swapped, words, "the fixture's first two words must differ");
        assert_eq!(phrase_decode(&swapped), Err(PhraseError::Checksum));
    }

    #[test]
    fn a_thousand_seeds_round_trip() {
        for i in 0u32..1000 {
            let seed = sha3_256(&[b"citadel-phrase-round-trip", &i.to_be_bytes()]);
            assert_eq!(phrase_decode(&phrase_encode(&seed)), Ok(seed), "seed {i}");
        }
    }

    #[test]
    fn a_bip39_phrase_is_not_a_citadel_phrase() {
        let mut bip39 = ["abandon"; PHRASE_WORDS];
        bip39[23] = "art";
        assert_eq!(phrase_decode(&bip39), Err(PhraseError::Checksum));
    }
}
