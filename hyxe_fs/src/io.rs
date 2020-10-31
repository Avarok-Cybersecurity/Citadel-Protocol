use std::path::Path;
use serde::Serialize;
use std::fmt::{Formatter, Error, Debug};
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(dead_code)]
fn merge_dir_and_filename<'a>(directory: &'a mut str, filename: &'a str) -> String {
    let mut builder = String::new();

    if !(directory.ends_with("/") || directory.ends_with("\\")) {
        builder.push('/');
    }

    (directory.to_owned() + filename).replace("\\", "/")
}

#[cfg(any(target_os = "windows"))]
#[allow(dead_code)]
fn merge_dir_and_filename<'a>(directory: &'a str, filename: &'a str) -> String {
    let mut builder = String::new();
    builder.push_str(directory);

    if !(directory.ends_with("/") || directory.ends_with("\\")) {
        builder.push('\\');
    }

    (builder + filename).replace("\\", "/")
}

/// Conveniant serialization methods for types that #[derive(Serialize, Deserialize)]
pub trait SyncIO where Self: Sized {
    /// Serializes a bincode type to the local FS
    fn serialize_to_local_fs<P: AsRef<Path>>(&self, location: P) -> Result<(), FsError<String>>;
    /// Deserializes a bincode type from the local FS
    fn deserialize_from_local_fs<P: AsRef<Path>>(location: P) -> Result<Self, FsError<String>>;
    /// Serializes a bincode type to a byte vector
    fn serialize_to_vector(&self) -> Result<Vec<u8>, FsError<String>>;
    /// Deserialized a bincode type from a byte vector
    fn deserialize_from_vector<T: AsRef<[u8]>>(input: &T) -> Result<Self, FsError<String>>;
}

impl<T: Serialize + DeserializeOwned + Sized> SyncIO for T {
    fn serialize_to_local_fs<P: AsRef<Path>>(&self, location: P) -> Result<(), FsError<String>> {
        if let Some(parent_path) = location.as_ref().parent() {
            crate::system_file_manager::make_dir_all_blocking(parent_path)?;
        }

        crate::system_file_manager::write(self, location)
    }

    fn deserialize_from_local_fs<P: AsRef<Path>>(location: P) -> Result<Self, FsError<String>> {
        crate::system_file_manager::read(location)
    }

    fn serialize_to_vector(&self) -> Result<Vec<u8>, FsError<String>> {
        crate::system_file_manager::type_to_bytes(self)
    }

    fn deserialize_from_vector<B: AsRef<[u8]>>(input: &B) -> Result<Self, FsError<String>> {
        crate::system_file_manager::bytes_to_type(input.as_ref())
    }
}

