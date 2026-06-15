//! Account Loading and File Management
//!
//! This module provides functionality for loading and managing serialized client network accounts (CNACs)
//! and other file-based data structures in the Citadel network.
//!
//! # Features
//!
//! * Load client network accounts from filesystem or OPFS
//! * Support for both personal and impersonal accounts
//! * Generic file type loading by extension
//! * Efficient deserialization of stored data
//! * Error handling for IO and deserialization operations
//!
//! # Important Notes
//!
//! * Account loading is performed non-recursively within specified directories
//! * Failed deserialization attempts are logged but do not halt the loading process
//! * Both personal and impersonal accounts are loaded and merged into a single collection
//! * All I/O is performed through the [`FileIO`] abstraction

use crate::backend::file_io::FileIO;
use crate::directory_store::*;
use crate::hypernode_account::CNAC_SERIALIZED_EXTENSION;
use crate::misc::AccountError;
use crate::prelude::ClientNetworkAccount;
use citadel_crypt::ratchets::Ratchet;
use serde::de::DeserializeOwned;
use std::collections::HashMap;

/// Loads all locally-stored CNACs using the provided [`FileIO`] implementation.
#[allow(unused_results)]
pub async fn load_cnac_files<R: Ratchet, Fcm: Ratchet>(
    ds: &DirectoryStore,
    file_io: &dyn FileIO,
) -> Result<HashMap<u64, ClientNetworkAccount<R, Fcm>>, AccountError> {
    let hyxe_nac_dir_impersonal = ds.nac_dir_impersonal.as_str();
    let hyxe_nac_dir_personal = ds.nac_dir_personal.as_str();

    let cnacs_impersonal = load_file_types_by_ext::<ClientNetworkAccount<R, Fcm>>(
        CNAC_SERIALIZED_EXTENSION,
        hyxe_nac_dir_impersonal,
        file_io,
    )
    .await?;
    let cnacs_personal = load_file_types_by_ext::<ClientNetworkAccount<R, Fcm>>(
        CNAC_SERIALIZED_EXTENSION,
        hyxe_nac_dir_personal,
        file_io,
    )
    .await?;
    log::trace!(target: "citadel", "[CNAC Loader] Impersonal client network accounts loaded: {} | Personal client network accounts loaded: {}", cnacs_impersonal.len(), cnacs_personal.len());

    Ok(cnacs_impersonal
        .into_iter()
        .chain(cnacs_personal)
        .map(|(cnac, _path)| {
            let cid = cnac.get_cid();
            (cid, cnac)
        })
        .collect())
}

/// Returns an array of a specific deserialized item types filtered by the extension type.
/// Returns any possibly existent types that [A] exist within the specific directory (no recursion),
/// [B] are files, [C] contain the appropriate file extension, and [D] files which are successfully
/// deserialized. Further, it returns the path string associated with the file.
pub async fn load_file_types_by_ext<D: DeserializeOwned>(
    ext: &str,
    path: &str,
    file_io: &dyn FileIO,
) -> Result<Vec<(D, String)>, AccountError> {
    let entries = file_io.read_dir(path).await?;
    let files: Vec<String> = entries
        .into_iter()
        .filter(|entry| entry.is_file && entry.extension.as_deref() == Some(ext))
        .map(|entry| entry.path)
        .collect();

    let mut ret = Vec::new();

    for file_path in files {
        match read::<D>(&file_path, file_io).await {
            Ok(val) => {
                ret.push((val, file_path));
            }
            Err(err) => {
                log::error!(target: "citadel", "Error loading: {err:?}");
            }
        }
    }

    Ok(ret)
}

/// Reads the given path as the given type, D
pub async fn read<D: DeserializeOwned>(
    path: &str,
    file_io: &dyn FileIO,
) -> Result<D, AccountError> {
    let data = file_io.read_file(path).await?;
    bincode::deserialize(&data).map_err(|err| AccountError::io(err.to_string()))
}
