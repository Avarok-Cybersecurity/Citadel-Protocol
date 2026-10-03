//! Recovery codes: 128 random bits each, shown once as Crockford base32 in groups of four.
//!
//! The client generates them and sends only the encapsulation keys their seeds give. A code signs
//! in once, and only to a session that may enrol a security key and set the policy.

use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use rand::RngCore;
use zeroize::Zeroizing;

/// How many codes an account is given at a time.
pub const RECOVERY_CODE_COUNT: usize = 10;

const CODE_BYTES: usize = 16;
/// 128 bits in 5-bit symbols.
const CODE_SYMBOLS: usize = 26;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// One recovery code.
pub struct RecoveryCode(Zeroizing<[u8; CODE_BYTES]>);

impl RecoveryCode {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; CODE_BYTES]);
        rand::thread_rng().fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    /// A fresh set of [`RECOVERY_CODE_COUNT`] codes.
    pub fn generate_set() -> Vec<Self> {
        (0..RECOVERY_CODE_COUNT).map(|_| Self::generate()).collect()
    }

    pub(crate) fn as_bytes(&self) -> &[u8; CODE_BYTES] {
        &self.0
    }

    /// The code as the user sees it, e.g. `7K3M-…-QX`.
    pub fn display(&self) -> Zeroizing<String> {
        let mut value = u128::from_be_bytes(*self.0);
        let mut symbols = [0u8; CODE_SYMBOLS];
        for slot in symbols.iter_mut().rev() {
            *slot = ALPHABET[(value & 0x1F) as usize];
            value >>= 5;
        }
        let mut out = Zeroizing::new(String::with_capacity(CODE_SYMBOLS + CODE_SYMBOLS / 4));
        for (i, symbol) in symbols.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(*symbol as char);
        }
        symbols.fill(0);
        out
    }

    /// Reads a code the user typed: case-insensitive, hyphens and spaces ignored, and the
    /// Crockford confusables `O`→`0` and `I`/`L`→`1` accepted.
    pub fn parse(typed: &str) -> Result<Self, AccountError> {
        let invalid = || error!(ErrorCode::PqSignInMalformed, "a recovery code");
        let mut value: u128 = 0;
        let mut count = 0usize;
        for c in typed.chars().filter(|c| *c != '-' && !c.is_whitespace()) {
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                other => other,
            };
            let digit = ALPHABET
                .iter()
                .position(|a| *a as char == c)
                .ok_or_else(invalid)?;
            // The leading symbol holds only the top 3 bits of the 130 the 26 symbols could carry.
            if count == 0 && digit > 0b111 {
                return Err(invalid());
            }
            value = (value << 5) | digit as u128;
            count += 1;
        }
        if count != CODE_SYMBOLS {
            return Err(invalid());
        }
        Ok(Self(Zeroizing::new(value.to_be_bytes())))
    }
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_survives_display_and_sloppy_typing() {
        for _ in 0..64 {
            let code = RecoveryCode::generate();
            let shown = code.display();
            assert_eq!(shown.len(), CODE_SYMBOLS + 6);
            assert_eq!(*RecoveryCode::parse(&shown).unwrap().0, *code.0);
            let sloppy = shown.to_lowercase().replace('-', " ");
            assert_eq!(*RecoveryCode::parse(&sloppy).unwrap().0, *code.0);
        }
    }

    #[test]
    fn confusable_letters_read_as_digits() {
        let code = RecoveryCode::parse("0000-0000-0000-0000-0000-0000-01").unwrap();
        let same = RecoveryCode::parse("oooo-OOOO-0000-0000-0000-0000-oI").unwrap();
        assert_eq!(*code.0, *same.0);
    }

    #[test]
    fn wrong_lengths_symbols_and_overflow_are_refused() {
        assert!(RecoveryCode::parse("ABCD").is_err());
        assert!(RecoveryCode::parse("0000-0000-0000-0000-0000-0000-0U").is_err());
        assert!(RecoveryCode::parse("Z000-0000-0000-0000-0000-0000-00").is_err());
        assert!(RecoveryCode::parse("0000-0000-0000-0000-0000-0000-000").is_err());
    }

    #[test]
    fn a_set_has_the_advertised_size_and_no_repeats() {
        let set = RecoveryCode::generate_set();
        assert_eq!(set.len(), RECOVERY_CODE_COUNT);
        for (i, a) in set.iter().enumerate() {
            assert!(set[i + 1..].iter().all(|b| *a.0 != *b.0));
        }
    }
}
