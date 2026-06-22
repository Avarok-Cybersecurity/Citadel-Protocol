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
use bytes::BufMut;
use bytes::BytesMut;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

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
        bincode::deserialize_from(input.reader()).map_err(|err| {
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

    /// Serializes self into a buffer, appending to any existing contents.
    fn serialize_into_buf(&self, buf: &mut BytesMut) -> Result<(), AccountError>
    where
        Self: Serialize,
    {
        // Single-pass serialization directly into the buffer. The previous implementation first
        // called `bincode::serialized_size(self)` to pre-reserve exact capacity, but that is a
        // full second serialization pass over `self` on every outbound packet (this is invoked by
        // nearly every packet-crafter). `BytesMut`'s writer already grows amortized, so the sizing
        // pass was pure CPU overhead. The emitted bytes are byte-for-byte identical to before.
        bincode::serialize_into(buf.writer(), self).map_err(|err| {
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
    bincode::deserialize(bytes).map_err(|err| {
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
    fn serialize_into_buf_matches_vector_and_appends() {
        let s = sample();
        let expected = s.serialize_to_vector().unwrap();

        // Into an empty buffer: output must equal the canonical vector form byte-for-byte
        // (guards the single-pass optimization against any wire-format drift).
        let mut buf = BytesMut::new();
        s.serialize_into_buf(&mut buf).unwrap();
        assert_eq!(&buf[..], &expected[..]);

        // Into a non-empty buffer: serialization must APPEND, leaving the existing prefix
        // intact, because packet crafters write a header before the serialized body.
        let prefix = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let mut buf = BytesMut::from(&prefix[..]);
        s.serialize_into_buf(&mut buf).unwrap();
        assert_eq!(&buf[..prefix.len()], &prefix[..]);
        assert_eq!(&buf[prefix.len()..], &expected[..]);
        // The appended body still round-trips independently of the prefix.
        assert_eq!(
            Sample::deserialize_from_vector(&buf[prefix.len()..]).unwrap(),
            s
        );
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
}
