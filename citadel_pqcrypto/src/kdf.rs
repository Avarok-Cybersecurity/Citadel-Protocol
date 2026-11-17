//! The key schedule a key exchange's shared secret feeds.
//!
//! The first exchange derives `S_0' = SHA3-512(S_0 || psks)`, split into Alice's and Bob's keys.
//! Every later one folds the previous chain in: `T = SHA3-512(C_n || S_n || psks)`, then
//! `A = SHA3-256(A_n ^ T[..32])` and `B = SHA3-256(B_n ^ T[32..])`. The chain is always
//! `C = SHA3-256(A ^ B)`. Inputs are hashed incrementally and every intermediate lives in a buffer
//! that is wiped when it goes out of scope, so no copy of the secret, the pre-shared keys or the
//! derived keys is left behind in freed memory.

use crate::constructor_opts::RecursiveChain;
use citadel_types::errors::Error;
use sha3::Digest;
use zeroize::Zeroizing;

/// Alice's key, Bob's key and the chain that the next exchange folds in.
pub(crate) struct DerivedKeys {
    pub chain: RecursiveChain,
    pub alice: Zeroizing<[u8; 32]>,
    pub bob: Zeroizing<[u8; 32]>,
}

fn xor32(a: &[u8], b: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        *o = x ^ y;
    }
    out
}

fn sha3_256(input: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&sha3::Sha3_256::digest(input));
    out
}

pub(crate) fn derive_keys<T: AsRef<[u8]>>(
    shared_secret: &[u8],
    previous: Option<&RecursiveChain>,
    psks: &[T],
) -> Result<DerivedKeys, Error> {
    let mut hasher = sha3::Sha3_512::new();
    if let Some(prev) = previous {
        hasher.update(prev.chain);
    }
    hasher.update(shared_secret);
    for psk in psks {
        hasher.update(psk.as_ref());
    }
    let mut temp = Zeroizing::new([0u8; 64]);
    temp.copy_from_slice(&hasher.finalize());
    let (temp_alice, temp_bob) = temp.split_at(32);

    let (alice, bob) = match previous {
        Some(prev) => (
            sha3_256(&xor32(&prev.alice, temp_alice)[..]),
            sha3_256(&xor32(&prev.bob, temp_bob)[..]),
        ),
        None => {
            let mut alice = Zeroizing::new([0u8; 32]);
            let mut bob = Zeroizing::new([0u8; 32]);
            alice.copy_from_slice(temp_alice);
            bob.copy_from_slice(temp_bob);
            (alice, bob)
        }
    };
    let chain = sha3_256(&xor32(&alice[..], &bob[..])[..]);
    let chain = RecursiveChain::new(&chain[..], &alice[..], &bob[..], previous.is_none())
        .ok_or(Error::invalid_length())?;
    Ok(DerivedKeys { chain, alice, bob })
}

#[cfg(test)]
mod tests {
    use super::derive_keys;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Known answers recorded from the schedule as it stood before the inputs were hashed
    /// incrementally; the keys a peer derives must not change.
    #[test]
    fn the_schedule_matches_its_known_answers() {
        let ss = [8u8; 32];
        let psks = [b"psk".as_slice()];
        let first = derive_keys(&ss, None, &psks).unwrap();
        assert!(first.chain.first);
        assert_eq!(
            hex(&first.chain.chain),
            "5a2f487ffa0282a2b3c29ba12da55a53d816ff7e178444ad32a50107eb08eb05"
        );
        assert_eq!(
            hex(&first.alice[..]),
            "5c07b26f196ca2cbd0561ef7c429210b1d19ab21158219a3bbbaddaba4cca650"
        );
        let next = derive_keys(&ss, Some(&first.chain), &psks).unwrap();
        assert!(!next.chain.first);
        assert_eq!(
            hex(&next.chain.chain),
            "f637bce7fc8a14354d59acc1abb1577fd71e25e625912a1a64474f82841b06da"
        );
        assert_eq!(
            hex(&next.alice[..]),
            "12cec1b9d0edbed4cf1f1e4441d0009093fa802194ae7ff7578f9d14f8408790"
        );
        assert_eq!(
            hex(&next.bob[..]),
            "f5197457e19a88376d3b85b6e8c2c94171bf19828cebcff1e5bd8b6a36c57ff3"
        );
    }
}
