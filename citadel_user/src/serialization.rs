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
        bincode::deserialize_from(input.reader())
            .map_err(|err| AccountError::Generic(err.to_string()))
    }

    /// Deserializes in-place
    fn deserialize_in_place<'a, R, T>(reader: R, place: &mut T) -> Result<(), AccountError>
    where
        T: serde::de::Deserialize<'a>,
        R: BincodeRead<'a>,
    {
        bincode::deserialize_in_place(reader, place)
            .map_err(|err| AccountError::Generic(err.to_string()))
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
            .map_err(|_| AccountError::Generic("Bad ser".to_string()))
    }

    /// Serializes directly into a slice
    fn serialize_into_slice(&self, slice: &mut [u8]) -> Result<(), AccountError>
    where
        Self: Serialize,
    {
        bincode::serialize_into(slice, self).map_err(|err| AccountError::Generic(err.to_string()))
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
    bincode::deserialize(bytes).map_err(|err| AccountError::IoError(err.to_string()))
}

/// Converts a type, D to Vec<u8>
fn type_to_bytes<D: Serialize>(input: D) -> Result<Vec<u8>, AccountError> {
    bincode::serialize(&input).map_err(|err| AccountError::IoError(err.to_string()))
}
