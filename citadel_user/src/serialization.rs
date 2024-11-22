use crate::misc::AccountError;
use bincode2::BincodeRead;
use bytes::BufMut;
use bytes::BytesMut;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Convenient serialization methods for types that #[derive(Serialize, Deserialize)]
pub trait SyncIO {
    /// Serializes a bincode2 type to a byte vector
    fn serialize_to_vector(&self) -> Result<Vec<u8>, AccountError>
    where
        Self: Serialize,
    {
        type_to_bytes(self)
    }
    /// Deserialized a bincode2 type from a byte vector
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
        bincode2::deserialize_from(input.reader())
            .map_err(|err| AccountError::Generic(err.to_string()))
    }

    /// Deserializes in-place
    fn deserialize_in_place<'a, R, T>(reader: R, place: &mut T) -> Result<(), AccountError>
    where
        T: serde::de::Deserialize<'a>,
        R: BincodeRead<'a>,
    {
        bincode2::deserialize_in_place(reader, place)
            .map_err(|err| AccountError::Generic(err.to_string()))
    }

    /// Serializes self into a buffer
    fn serialize_into_buf(&self, buf: &mut BytesMut) -> Result<(), AccountError>
    where
        Self: Serialize,
    {
        bincode2::serialized_size(self)
            .and_then(|amt| {
                buf.reserve(amt as usize);
                bincode2::serialize_into(buf.writer(), self)
            })
            .map_err(|_| AccountError::Generic("Bad ser".to_string()))
    }

    /// Serializes directly into a slice
    fn serialize_into_slice(&self, slice: &mut [u8]) -> Result<(), AccountError>
    where
        Self: Serialize,
    {
        bincode2::serialize_into(slice, self).map_err(|err| AccountError::Generic(err.to_string()))
    }

    /// Returns the expected size of the serialized objects
    fn serialized_size(&self) -> Option<usize>
    where
        Self: Serialize,
    {
        bincode2::serialized_size(self).ok().map(|res| res as usize)
    }
}

impl<'a, T> SyncIO for T where T: Serialize + Deserialize<'a> + Sized {}

/// Deserializes the bytes, T, into type D
fn bytes_to_type<'a, D: Deserialize<'a>>(bytes: &'a [u8]) -> Result<D, AccountError> {
    bincode2::deserialize(bytes).map_err(|err| AccountError::IoError(err.to_string()))
}

/// Converts a type, D to Vec<u8>
fn type_to_bytes<D: Serialize>(input: D) -> Result<Vec<u8>, AccountError> {
    bincode2::serialize(&input).map_err(|err| AccountError::IoError(err.to_string()))
}
