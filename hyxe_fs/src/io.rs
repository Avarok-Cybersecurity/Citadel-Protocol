use std::path::Path;
use serde::{Serialize, Deserialize};
use std::fmt::{Formatter, Error, Debug};
use bytes::BytesMut;
use bytes::BufMut;
use serde::de::DeserializeOwned;

/// Default Error type for this crate
pub enum FsError<T: ToString> {
    /// Input/Output error. Used for possibly failed Serialization/Deserialization of underlying datatypes
    IoError(T),
    /// Generic error
    Generic(T)
}

impl<T: ToString> FsError<T> {
    /// Returns the error message
    pub fn to_string(&self) -> String {
        match self {
            FsError::IoError(t) => t.to_string(),
            FsError::Generic(t) => t.to_string()
        }
    }
}

impl<T: ToString> Debug for FsError<T> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.to_string())
    }
}

impl<T: ToString> std::fmt::Display for FsError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

/// Used for specifying the operation when writing to the disk
pub enum IoMode {
    /// Overwrite the file, deleting the previously existing content and creating one anew
    Overwrite,
    /// Appends to the existing file. If the file does not exist, then an Error is returned
    Append,
    /// Writes to the file if the file does not exist
    WriteIfNonExists
}

/// Conveniant serialization methods for types that #[derive(Serialize, Deserialize)]
pub trait SyncIO {
    /// Serializes a bincode type to the local FS
    fn serialize_to_local_fs<'a, P: AsRef<Path>>(&self, location: P) -> Result<(), FsError<String>>
        where Self: Serialize + Sized {
        if let Some(parent_path) = location.as_ref().parent() {
            crate::system_file_manager::make_dir_all_blocking(parent_path)?;
        }

        crate::system_file_manager::write(self, location)
    }
    /// Deserializes a bincode type from the local FS
    fn deserialize_from_local_fs<P: AsRef<Path>>(location: P) -> Result<Self, FsError<String>>
        where Self: DeserializeOwned {
        crate::system_file_manager::read(location)
    }
    /// Serializes a bincode type to a byte vector
    fn serialize_to_vector(&self) -> Result<Vec<u8>, FsError<String>>
        where Self: Serialize {
        crate::system_file_manager::type_to_bytes(self)
    }
    /// Deserialized a bincode type from a byte vector
    fn deserialize_from_vector<'a>(input: &'a [u8]) -> Result<Self, FsError<String>>
        where Self: Deserialize<'a> {
        crate::system_file_manager::bytes_to_type(input)
    }

    /// Deserializes from an owned buffer
    fn deserialize_from_owned_vector(input: Vec<u8>) -> Result<Self, FsError<String>> where Self: DeserializeOwned {
        use bytes::Buf;
        bincode2::deserialize_from(input.reader()).map_err(|err| FsError::Generic(err.to_string()))
    }

    /// Serializes self into a buffer
    fn serialize_into_buf(&self, buf: &mut BytesMut) -> Result<(), FsError<String>>
        where Self: Serialize {
        bincode2::serialized_size(self)
            .and_then(|amt| {
                buf.reserve(amt as usize);
                bincode2::serialize_into(buf.writer(), self)
            }).map_err(|_| FsError::Generic("Bad ser".to_string()))
    }

    /// Returns the expected size of the serialized objects
    fn serialized_size(&self) -> Option<usize>
        where Self: Serialize {
        bincode2::serialized_size(self).ok()
            .map(|res| res as usize)
    }
}

impl<'a, T> SyncIO for T where T: Serialize + Deserialize<'a> + Sized {}

