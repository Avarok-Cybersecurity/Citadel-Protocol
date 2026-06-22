//! # Serialization Support
//!
//! This module provides efficient serialization and deserialization functionality
//! for Citadel Protocol types using bincode. It offers a trait-based approach
//! for consistent serialization across the system.
//!
//! ## Features
//!
//! * **Binary Serialization**
//!   - Vector-based serialization
//!   - Buffer-based serialization
//!   - In-place deserialization
//!   - Size estimation
//!
//! * **Format Support**
//!   - Bincode encoding
//!   - Bytes buffer integration
//!   - Slice operations
//!   - Reader/Writer support
//!
//! * **Performance Features**
//!   - Size pre-allocation
//!   - In-place operations
//!   - Buffer reuse
//!   - Memory efficiency
//!
//! ## Usage Example
//!
//! ```rust
//! use citadel_user::serialization::SyncIO;
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct User {
//!     id: u64,
//!     name: String,
//! }
//!
//! fn handle_serialization() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create test data
//!     let user = User {
//!         id: 1234,
//!         name: "Alice".to_string(),
//!     };
//!     
//!     // Serialize to vector
//!     let bytes = user.serialize_to_vector()?;
//!     
//!     // Deserialize from vector
//!     let decoded: User = User::deserialize_from_vector(&bytes)?;
//!     assert_eq!(decoded.id, user.id);
//!     assert_eq!(decoded.name, user.name);
//!     
//!     // Use buffer for efficiency
//!     let mut buffer = bytes::BytesMut::with_capacity(64);
//!     user.serialize_into_buf(&mut buffer)?;
//!     
//!     // Get serialized size
//!     if let Some(size) = user.serialized_size() {
//!         println!("Serialized size: {} bytes", size);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Important Notes
//!
//! * Types must implement `Serialize` and `Deserialize`
//! * Buffer operations are more efficient for repeated use
//! * Size estimation helps with buffer pre-allocation
//! * In-place deserialization avoids allocations
//! * Error handling uses `AccountError` type
//!
//! ## Related Components
//!
//! * `AccountManager` - Uses serialization for persistence
//! * `ClientNetworkAccount` - Serializable account type
//! * `PersistenceHandler` - Handles serialized data storage
//! * `BackendType` - Storage backend configuration
//!

use crate::misc::AccountError;
use bincode::BincodeRead;
use bincode::Options;
use bytes::BufMut;
use bytes::BytesMut;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Builds the bincode configuration used for deserializing untrusted input.
///
/// This is byte-for-byte identical to the configuration used by the free
/// `bincode::deserialize` / `bincode::deserialize_from` functions
/// (fixint encoding, little-endian, trailing bytes allowed) with one addition:
/// a byte limit equal to the length of the input buffer.
///
/// A correctly-encoded value can never require reading more bytes than the
/// input itself contains, so the limit never rejects a legitimate message.
/// What it does prevent is a hostile peer sending a tiny packet whose internal
/// length prefix (e.g. for a `Vec<u8>` or `String` field) claims billions of
/// elements: without a limit, bincode honors that prefix and attempts the
/// corresponding heap allocation *before* discovering the bytes are not there,
/// turning a few-byte packet into a multi-gigabyte allocation (remote
/// memory-exhaustion DoS). With the limit, the oversized length is rejected up
/// front with a clean `SizeLimit` error and no allocation occurs.
#[inline]
fn limited_options(input_len: usize) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(input_len as u64)
}

/// Convenient serialization methods for types that #[derive(Serialize, Deserialize)]
pub trait SyncIO {
    /// Serializes a bincode type to a byte vector
    fn serialize_to_vector(&self) -> Result<Vec<u8>, AccountError>
    where
        Self: Serialize,
    {
        type_to_bytes(self)
    }
    /// Deserialized a bincode type from a byte vector
    fn deserialize_from_vector<'a>(input: &'a [u8]) -> Result<Self, AccountError>
    where
        Self: Deserialize<'a>,
    {
        bytes_to_type(input)
    }

    /// Deserializes from an owned buffer
    fn deserialize_from_owned_vector(input: Vec<u8>) -> Result<Self, AccountError>
    where
        Self: DeserializeOwned,
    {
        use bytes::Buf;
        // Cap the allocation at the input length to defeat length-prefix
        // allocation bombs from untrusted peers (see `limited_options`).
        // Wire-compatible with the previous `bincode::deserialize_from` call.
        limited_options(input.len())
            .deserialize_from(input.reader())
            .map_err(|err| {
                citadel_io::error!(
                    citadel_io::ErrorCode::DeserializationFailed,
                    err.to_string()
                )
            })
    }

    /// Deserializes in-place
    fn deserialize_in_place<'a, R, T>(reader: R, place: &mut T) -> Result<(), AccountError>
    where
        T: serde::de::Deserialize<'a>,
        R: BincodeRead<'a>,
    {
        bincode::deserialize_in_place(reader, place).map_err(|err| {
            citadel_io::error!(
                citadel_io::ErrorCode::DeserializationFailed,
                err.to_string()
            )
        })
    }

    /// Serializes self into a buffer
    fn serialize_into_buf(&self, buf: &mut BytesMut) -> Result<(), AccountError>
    where
        Self: Serialize,
    {
        bincode::serialized_size(self)
            .and_then(|amt| {
                buf.reserve(amt as usize);
                bincode::serialize_into(buf.writer(), self)
            })
            .map_err(|err| {
                citadel_io::error!(citadel_io::ErrorCode::SerializationFailed, err.to_string())
            })
    }

    /// Serializes directly into a slice
    fn serialize_into_slice(&self, slice: &mut [u8]) -> Result<(), AccountError>
    where
        Self: Serialize,
    {
        bincode::serialize_into(slice, self).map_err(|err| {
            citadel_io::error!(citadel_io::ErrorCode::SerializationFailed, err.to_string())
        })
    }

    /// Returns the expected size of the serialized objects
    fn serialized_size(&self) -> Option<usize>
    where
        Self: Serialize,
    {
        bincode::serialized_size(self).ok().map(|res| res as usize)
    }
}

impl<'a, T> SyncIO for T where T: Serialize + Deserialize<'a> + Sized {}

/// Deserializes the bytes, T, into type D
fn bytes_to_type<'a, D: Deserialize<'a>>(bytes: &'a [u8]) -> Result<D, AccountError> {
    // Cap the allocation at the input length to defeat length-prefix allocation
    // bombs from untrusted peers (see `limited_options`). Wire-compatible with
    // the previous `bincode::deserialize` call.
    limited_options(bytes.len())
        .deserialize(bytes)
        .map_err(|err| {
            citadel_io::error!(
                citadel_io::ErrorCode::DeserializationFailed,
                err.to_string()
            )
        })
}

/// Converts a type, D to Vec<u8>
fn type_to_bytes<D: Serialize>(input: D) -> Result<Vec<u8>, AccountError> {
    bincode::serialize(&input).map_err(|err| {
        citadel_io::error!(citadel_io::ErrorCode::SerializationFailed, err.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Sample {
        id: u64,
        name: String,
        flags: Vec<bool>,
    }

    fn sample() -> Sample {
        Sample {
            id: 1234,
            name: "alice".to_string(),
            flags: vec![true, false, true],
        }
    }

    #[test]
    fn vector_roundtrip() {
        let s = sample();
        let bytes = s.serialize_to_vector().unwrap();
        assert_eq!(Sample::deserialize_from_vector(&bytes).unwrap(), s);
        assert_eq!(Sample::deserialize_from_owned_vector(bytes).unwrap(), s);
    }

    #[test]
    fn buf_and_slice_roundtrip() {
        let s = sample();
        let mut buf = BytesMut::with_capacity(8);
        s.serialize_into_buf(&mut buf).unwrap();
        assert_eq!(Sample::deserialize_from_vector(&buf).unwrap(), s);

        let size = s.serialized_size().unwrap();
        assert_eq!(size, s.serialize_to_vector().unwrap().len());
        let mut slice = vec![0u8; size];
        s.serialize_into_slice(&mut slice).unwrap();
        assert_eq!(Sample::deserialize_from_vector(&slice).unwrap(), s);
    }

    #[test]
    fn serialize_into_undersized_slice_errors() {
        let s = sample();
        let mut tiny = [0u8; 1];
        assert!(s.serialize_into_slice(&mut tiny).is_err());
    }

    #[test]
    fn deserialize_garbage_errors() {
        assert!(Sample::deserialize_from_vector(&[0xFFu8; 2]).is_err());
        assert!(Sample::deserialize_from_owned_vector(vec![0xFFu8; 2]).is_err());
    }

    /// A hostile peer can hand-craft a tiny payload whose internal length prefix
    /// claims a huge number of elements. Before the byte-limit hardening, bincode
    /// would honor the prefix and attempt the corresponding (multi-gigabyte) heap
    /// allocation before noticing the bytes are absent — a remote
    /// memory-exhaustion DoS. The deserializer must now reject these cheaply.
    #[test]
    fn rejects_oversized_length_prefix() {
        // `Vec<u8>` is length-prefixed by a fixint u64 (8 little-endian bytes).
        // Claim ~18 EB of elements but supply no payload.
        let mut malicious = u64::MAX.to_le_bytes().to_vec(); // length prefix = u64::MAX
        malicious.extend_from_slice(&[0u8; 4]); // a few real bytes, far fewer than claimed

        // Must error (not allocate/OOM). The wrapper caps the limit at the input
        // length, so the oversized prefix is rejected up front.
        assert!(Vec::<u8>::deserialize_from_vector(&malicious).is_err());
        assert!(Vec::<u8>::deserialize_from_owned_vector(malicious.clone()).is_err());

        // The same protection applies to `String` fields.
        assert!(String::deserialize_from_vector(&malicious).is_err());
    }

    /// The byte limit must never reject a legitimately-encoded value: a valid
    /// encoding can never need to read more bytes than the buffer it came from.
    #[test]
    fn limit_preserves_valid_roundtrip_for_large_payloads() {
        // A genuinely large (but self-consistent) payload round-trips fine,
        // because the limit equals the encoded length.
        let big = Sample {
            id: 9,
            name: "n".repeat(100_000),
            flags: vec![true; 50_000],
        };
        let bytes = big.serialize_to_vector().unwrap();
        assert_eq!(Sample::deserialize_from_vector(&bytes).unwrap(), big);
        assert_eq!(Sample::deserialize_from_owned_vector(bytes).unwrap(), big);
    }
}
