use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use crate::prelude::FsError;
//use tokio::fs::read_dir;
use serde::{Serialize, Deserialize};
//use async_std::prelude::*;
use futures::future::TryFutureExt;

/// Returns an array of a specific deserialized item types filtered by the extension type.
/// Returns any possibly existent types that [A] exist within the specific directory (no recursion),
/// [B] are files, [C] contain the appropriate file extension, and [D] files which are successfully
/// serialized. Further, it returns the PathBuf associated with the file
///
/// Useful for returning NACs
pub fn load_file_types_by_ext<D: DeserializeOwned, P: AsRef<Path>>(ext: &str, path: P) -> Result<Vec<(D, PathBuf)>, FsError<String>> {
    let mut dir = std::fs::read_dir(path.as_ref()).map_err(|err| FsError::IoError(err.to_string()))?;
    let mut files = Vec::new();
    while let Some(Ok(child)) = dir.next() {
        let path_buf = child.path();
        if let Some(extension) = path_buf.extension() {
            if extension == ext && path_buf.is_file() {
                files.push(path_buf);
            }
        }
    }

    let mut ret = Vec::new();

    for file in files {
        //log::info!("[SystemFileManager] Checking {}", file.clone().into_os_string().into_string().unwrap());
        match read::<D, _>(&file) {
            Ok(val) => {
                ret.push((val, std::path::PathBuf::from(file.as_path())));
            },

            Err(err) => {
                log::error!("Error loading: {}", err.to_string());
            }
        }
    }

    Ok(ret)
}


/// Asynchronously reads the given path as the given type, D.
pub async fn async_read<D: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<D, FsError<String>> {
    //let bytes: Vec<u8> = async_std::fs::read(path.as_ref()).await.map_err(|err| FsError::IoError(err.to_string()))?;
    let data = tokio::fs::read(path).map_err(|err| FsError::IoError(err.to_string())).await?;
    bincode_config().deserialize(data.as_slice())
        .map_err(|err| FsError::IoError(err.to_string()))
}

/// Reads the given path as the given type, D
pub fn read<D: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<D, FsError<String>> {
    std::fs::File::open(path.as_ref()).map_err(|err| FsError::IoError(err.to_string())).and_then(|file| {
        bincode_config().deserialize_from(std::io::BufReader::new(file))
            .map_err(|err| FsError::IoError(err.to_string()))
    })
}

/// Reads a file into a new string
pub async fn read_file_to_string<P: AsRef<Path>>(path: P) -> Result<String, FsError<String>> {
    tokio::fs::read_to_string(path).map_err(|err| FsError::IoError(err.to_string())).await
}

/// Writes a serializable object to the desired path
pub fn write<D: Sized + Serialize, P: AsRef<Path>>(object: &D, path: P) -> Result<(), FsError<String>> {
    std::fs::File::create(path)
        .map_err(|err| FsError::IoError(err.to_string()))
        .and_then(|file| {
            let buf_writer = &mut std::io::BufWriter::new(file);
            // change: use BufWriter, as it's "50x" faster https://stackoverflow.com/questions/49983101/serialization-of-large-struct-to-disk-with-serde-and-bincode-is-slow?noredirect=1&lq=1
            bincode_config().serialize_into(buf_writer, object).map_err(|err| FsError::IoError(err.to_string()))
        })
}

/// Creates all missing directories if the path contains missing folders
pub async fn make_dir_all<P: AsRef<Path>>(path: P) -> Result<(), FsError<String>> {
    tokio::fs::create_dir_all(path.as_ref()).await.map_err(|err| FsError::IoError(err.to_string()))
}

/// Blocking version of make_dir_all
pub fn make_dir_all_blocking<P: AsRef<Path>>(path: P) -> Result<(), FsError<String>> {
    std::fs::create_dir_all(path.as_ref()).map_err(|err| FsError::IoError(err.to_string()))
}

/// Asynchronously writes the object to the HD
pub async fn async_write<D: Sync + Serialize, P: AsRef<Path>>(object: &D, path: P) -> Result<(), FsError<String>> {
    let _ = tokio::fs::File::create(path.as_ref()).await?;

    let bytes = type_to_bytes(object)?;
    tokio::fs::write(path, bytes.as_slice()).await.map_err(|err| FsError::IoError(err.to_string()))
}

/// Creates an empty file, overwriting if already existent
pub async fn create_file<P: AsRef<Path>>(path: P) -> Result<(), FsError<String>> {
    tokio::fs::File::create(path).await.map(|_| ())
        .map_err(|err| FsError::IoError(err.to_string()))
}

/// Creates an empty file, overwriting if already existent
pub async fn create_file_with<P: AsRef<Path>>(path: P, data: &String) -> Result<(), FsError<String>> {
    let path_clone = path.as_ref().clone();
    tokio::fs::File::create(path.as_ref())
        .and_then(|_| tokio::fs::write(path_clone, data))
        .map_err(|err| FsError::IoError(err.to_string())).await
}

/// Deserializes the bytes, T, into type D
pub fn bytes_to_type<'a, D: Deserialize<'a>>(bytes: &'a [u8]) -> Result<D, FsError<String>> {
    bincode_config().deserialize(bytes)
        .map_err(|err| FsError::IoError(err.to_string()))
}

/// Converts a type, D to Vec<u8>
pub fn type_to_bytes<D: Serialize>(input: D) -> Result<Vec<u8>, FsError<String>> {
    bincode_config().serialize(&input)
        .map_err(|err| FsError::IoError(err.to_string()))
}

/// Deletes a file given an input to its location
pub async fn delete_file<P: AsRef<Path>>(path: P) -> Result<(), FsError<String>> {
    tokio::fs::remove_file(path).map_err(|err| FsError::IoError(err.to_string())).await
}

/// Deletes a file given an input to its location
pub fn delete_file_blocking<P: AsRef<Path>>(path: P) -> Result<(), FsError<String>> {
    std::fs::remove_file(path).map_err(|err| FsError::IoError(err.to_string()))
}

/// Writes raw bytes to a file
pub fn write_bytes_to<T: AsRef<[u8]>, P: AsRef<Path>>(bytes: T, path: P) -> Result<(), FsError<String>> {
    std::fs::write(path, bytes).map_err(|err| FsError::IoError(err.to_string()))
}

/// Writes raw bytes to a file asynchronously
pub async fn async_write_bytes_to<T: AsRef<[u8]>, P: AsRef<Path>>(bytes: T, path: P) -> Result<(), FsError<String>> {
    tokio::fs::write(path, bytes).await.map_err(|err| FsError::IoError(err.to_string()))
}

/// A limited config. Helps prevent oversized allocations from occurring when deserializing incompatible
/// objects
#[inline(always)]
#[allow(unused_results)]
pub(crate) fn bincode_config() -> bincode2::Config {
    let mut cfg = bincode2::config();
    cfg.limit(1000*1000*1000*4);
    cfg
}