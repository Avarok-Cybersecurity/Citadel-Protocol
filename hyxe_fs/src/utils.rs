use std::io::Write;
use serde::Serialize;
use crate::io::FsError;
use serde::de::DeserializeOwned;

/// Serializes into
pub fn serialize_into<W: Write, S: Serialize>(buf: W, source: S) -> Result<(), FsError<String>> {
    bincode2::serialize_into(buf, &source)
        .map_err(|err| FsError::IoError(err.to_string()))
}

/// Deserializes from bytes
pub fn deserialize_from<S: DeserializeOwned, R: AsRef<[u8]>>(source: R) -> Option<S> {
    bincode2::deserialize(source.as_ref()).ok()
}