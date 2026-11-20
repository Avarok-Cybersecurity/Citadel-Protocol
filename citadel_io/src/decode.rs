//! The one bincode configuration every decode of bytes this node did not produce goes through.
//!
//! It reads exactly what the free `bincode::deserialize` reads (fixint encoding, little-endian,
//! trailing bytes allowed), and adds one bound: a decode may consume no more bytes than the input
//! holds. A correctly encoded value never needs more, so the bound refuses nothing a peer could
//! legitimately send. A slice bounds itself (bincode checks a length against the bytes left); for
//! a reader, the bound makes bincode check a length against the input before it allocates, and
//! stop with `SizeLimit` when it does not fit.
//!
//! The free functions are denied workspace-wide (`clippy.toml`), so a new caller cannot bypass
//! this module by accident.

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::Deserialize;

/// The bounded options for an input of `input_len` bytes.
#[inline]
pub fn bounded_options(input_len: usize) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(input_len as u64)
}

/// Decodes `bytes` as a `T`, reading at most `bytes.len()` bytes.
#[inline]
pub fn deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> bincode::Result<T> {
    bounded_options(bytes.len()).deserialize(bytes)
}

/// Decodes an owned `T` from a reader over a buffer of `input_len` bytes.
#[inline]
pub fn deserialize_from<R: std::io::Read, T: DeserializeOwned>(
    reader: R,
    input_len: usize,
) -> bincode::Result<T> {
    bounded_options(input_len).deserialize_from(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Message {
        id: u64,
        name: String,
        blob: Vec<u8>,
    }

    fn message() -> Message {
        Message {
            id: 7,
            name: "seven".into(),
            blob: vec![1, 2, 3],
        }
    }

    /// Eight bytes of id, then a length prefix claiming a MiB of name, and nothing behind it.
    /// (Small enough that the unbounded reader's allocation, in a negative control, is harmless.)
    fn prefix_bomb() -> Vec<u8> {
        let mut bytes = 7u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(&(1u64 << 20).to_le_bytes());
        bytes
    }

    #[test]
    fn it_reads_what_the_free_function_writes() {
        let bytes = bincode::serialize(&message()).unwrap();
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), message());
        assert_eq!(
            deserialize_from::<_, Message>(&bytes[..], bytes.len()).unwrap(),
            message()
        );
    }

    #[test]
    fn a_length_prefix_beyond_the_input_stops_at_the_limit() {
        let bomb = prefix_bomb();
        // A slice bounds itself: bincode reads the claim against the bytes left and stops there.
        assert!(deserialize::<Message>(&bomb).is_err());
        // A reader does not, so the limit must: it refuses the claim before allocating for it.
        let err = deserialize_from::<_, Message>(&bomb[..], bomb.len()).unwrap_err();
        assert!(
            matches!(*err, bincode::ErrorKind::SizeLimit),
            "expected SizeLimit, got {err:?}"
        );
    }
}
