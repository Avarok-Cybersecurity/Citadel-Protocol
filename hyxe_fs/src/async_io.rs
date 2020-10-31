use async_trait::async_trait;
use serde::Serialize;
use crate::prelude::FsError;
use std::path::Path;
use serde::de::DeserializeOwned;

/// Convenient serialization methods for types that #[derive(Serialize, Deserialize)]
#[async_trait]
pub trait AsyncIO where Self: Sized {
    /// Serializes a bincode type to the local FS
    async fn async_serialize_to_local_fs<P: AsRef<Path> + Send + Sync>(&self, location: P) -> Result<(), FsError<String>>;
    /// Deserializes a bincode type from the local FS
    async fn async_deserialize_from_local_fs<P: AsRef<Path>+ Send + Sync>(location: P) -> Result<Self, FsError<String>>;
    /// Serializes a bincode type to a byte vector
    async fn async_serialize_to_vector(&self) -> Result<Vec<u8>, FsError<String>>;
    /// Deserialized a bincode type from a byte vector
    async fn async_deserialize_from_vector<R: AsRef<[u8]> + Send + Sync>(input: R) -> Result<Self, FsError<String>>;
}

#[async_trait]
impl<T: Sync + Serialize + DeserializeOwned + Sized + 'static> AsyncIO for T {
    async fn async_serialize_to_local_fs<P: AsRef<Path> + Send + Sync>(&self, location: P) -> Result<(), FsError<String>> {
        if let Some(parent_path) = location.as_ref().parent() {
            crate::system_file_manager::make_dir_all(parent_path).await?;
        }

        crate::system_file_manager::async_write(self, location).await
    }

    async fn async_deserialize_from_local_fs<P: AsRef<Path>+ Send + Sync>(location: P) -> Result<T, FsError<String>> {
        crate::system_file_manager::async_read(location.as_ref()).await
    }

    async fn async_serialize_to_vector(&self) -> Result<Vec<u8>, FsError<String>> {
        crate::system_file_manager::type_to_bytes(self)
    }

    async fn async_deserialize_from_vector<R: AsRef<[u8]> + Send + Sync>(input: R) -> Result<T, FsError<String>> {
        crate::system_file_manager::bytes_to_type(input.as_ref())
    }
}