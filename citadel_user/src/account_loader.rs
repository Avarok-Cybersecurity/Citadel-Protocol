//! Account Loading and File Management
//!
//! This module provides functionality for loading and managing serialized client network accounts (CNACs)
//! and other file-based data structures in the Citadel network.
//!
//! # Features
//!
//! * Load client network accounts from filesystem
//! * Support for both personal and impersonal accounts
//! * Generic file type loading by extension
//! * Efficient deserialization of stored data
//! * Error handling for IO and deserialization operations
//!
//! # Example
//!
//! ```rust, no_run
//! use citadel_user::account_loader;
//! use citadel_user::directory_store::DirectoryStore;
//! use citadel_crypt::ratchets::stacked::StackedRatchet;
//!
//! # fn get_store() -> DirectoryStore { todo!() }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a directory store for account management
//! let store = get_store();
//!
//! // Load all client network accounts
//! let accounts = account_loader::load_cnac_files::<StackedRatchet, StackedRatchet>(&store)?;
//!
//! // Process loaded accounts
//! for (cid, account) in accounts {
//!     println!("Loaded account with CID: {}", cid);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Important Notes
//!
//! * Account loading is performed non-recursively within specified directories
//! * Failed deserialization attempts are logged but do not halt the loading process
//! * Both personal and impersonal accounts are loaded and merged into a single collection
//! * File operations use buffered I/O for efficiency
//!
//! # Related Components
//!
//! * [`DirectoryStore`] - Manages filesystem paths for account storage
//! * [`ClientNetworkAccount`] - The primary account structure being loaded
//! * [`AccountError`] - Error handling for account operations
//! * [`Ratchet`] - Cryptographic operations for account security

use crate::directory_store::*;
use crate::hypernode_account::CNAC_SERIALIZED_EXTENSION;
use crate::misc::AccountError;
use crate::prelude::ClientNetworkAccount;
use citadel_crypt::ratchets::Ratchet;
use std::collections::HashMap;

/// Loads all locally-stored CNACs, as well as the highest CID (used to update local nac in case improper shutdown)
#[allow(unused_results)]
pub fn load_cnac_files<R: Ratchet, Fcm: Ratchet>(
    ds: &DirectoryStore,
) -> Result<HashMap<u64, ClientNetworkAccount<R, Fcm>>, AccountError> {
    let hyxe_nac_dir_impersonal = ds.nac_dir_impersonal.as_str();
    let hyxe_nac_dir_personal = ds.nac_dir_personal.as_str();

    let cnacs_impersonal = load_file_types_by_ext::<ClientNetworkAccount<R, Fcm>, _>(
        CNAC_SERIALIZED_EXTENSION,
        hyxe_nac_dir_impersonal,
    )?;
    let cnacs_personal = load_file_types_by_ext::<ClientNetworkAccount<R, Fcm>, _>(
        CNAC_SERIALIZED_EXTENSION,
        hyxe_nac_dir_personal,
    )?;
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

use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};

/// Returns an array of a specific deserialized item types filtered by the extension type.
/// Returns any possibly existent types that [A] exist within the specific directory (no recursion),
/// [B] are files, [C] contain the appropriate file extension, and [D] files which are successfully
/// serialized. Further, it returns the PathBuf associated with the file
///
/// Useful for returning NACs
pub fn load_file_types_by_ext<D: DeserializeOwned, P: AsRef<Path>>(
    ext: &str,
    path: P,
) -> Result<Vec<(D, PathBuf)>, AccountError> {
    let mut dir =
        std::fs::read_dir(path.as_ref()).map_err(|err| AccountError::IoError(err.to_string()))?;
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
        //log::trace!(target: "citadel", "[SystemFileManager] Checking {}", file.clone().into_os_string().into_string().unwrap());
        match read::<D, _>(&file) {
            Ok(val) => {
                ret.push((val, std::path::PathBuf::from(file.as_path())));
            }

            Err(err) => {
                log::error!(target: "citadel", "Error loading: {:?}", err);
            }
        }
    }

    Ok(ret)
}

/// Reads the given path as the given type, D
pub fn read<D: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<D, AccountError> {
    std::fs::File::open(path.as_ref())
        .map_err(|err| AccountError::IoError(err.to_string()))
        .and_then(|file| {
            bincode::deserialize_from(std::io::BufReader::new(file))
                .map_err(|err| AccountError::IoError(err.to_string()))
        })
}
