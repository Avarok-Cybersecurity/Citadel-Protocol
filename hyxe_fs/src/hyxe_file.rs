use std::borrow::Borrow;
use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use hyxe_crypt::prelude::*;

use crate::env::*;
use crate::hyxe_file::metadata_flags::{AUTHOR, DATE_CREATED, DATE_UPDATED};
use crate::io::FsError;
use crate::misc::{generate_random_string, get_present_formatted_timestamp, get_pathbuf};
use crate::async_io::AsyncIO;
use crate::prelude::SyncIO;
use hyxe_crypt::hyper_ratchet::HyperRatchet;

/// The extension for virtually hyperencrypted files
pub const HYXE_FILE_EXT: &str = "vxh";

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
/// The HyxeFile is a hyperencrypted file that can be safely stored to the disk.
/// Data is stored encrypted herein, and then saved locally to `real_file_path`\\`real_file_name`
pub struct HyxeFile {
    /// The Client ID that should be associated with the correct `drill_version` below
    cid: u64,
    /// The `drill_version` used to drill-shut the information
    drill_version: u32,
    /// The virtual file directory is for use in the [VirtualDirectory] FS. This is NOT
    /// to be confused with the local fs structure
    virtual_file_path: Option<PathBuf>,
    /// This is the primary content within the data
    data_encrypted_bytes: Option<Vec<u8>>,
    /// This is absolutely necessary
    security_level_drilled: SecurityLevel,
    #[serde(skip)]
    real_file_path: Option<PathBuf>,
    //we want to update this value onload for purpose of debugging stage transfer, as well as transfers between servers (unsafe!)
    /// This is the user-inputted name, e.g., "HelloFile.ext"
    file_name: String,
    /// Contains metadata
    metadata: HashMap<u8, String>,
}

impl HyxeFile {
    /// Creates an empty shell, allowing reads and writes to occur downstream
    /// the `real_file_name` is just the filename (directory is set later)
    #[allow(unused_results)]
    pub fn new<T: ToString, S: ToString>(author: T, cid: u64, real_file_name: S, virtual_file_path: Option<PathBuf>) -> Self {
        let mut metadata = HashMap::new();
        metadata.insert(AUTHOR, author.to_string());
        metadata.insert(DATE_CREATED, get_present_formatted_timestamp());

        Self {
            cid,
            drill_version: 0,
            virtual_file_path,
            data_encrypted_bytes: None,
            security_level_drilled: SecurityLevel::DIVINE,
            real_file_path: None,
            file_name: real_file_name.to_string(),
            metadata,
        }
    }

    /// Replaces the data within this HyxeFile. For security purposes, the drill applied is under the same restrictions* as `redrill_contents`.
    /// As such, this subroutine fails [1] if the drill supplied has an earlier (equal OK*) version to the currently existing data, or; [2] the
    /// drill supplied contains an unequal CID to this HyxeFiles.
    ///
    /// if `retrieve` is true, then data that is possibly pre-existing is returned. This is synonymous to a "get and set" operation
    pub fn replace_contents<B: ByteSlice>(&mut self, static_hyper_ratchet: &HyperRatchet, bytes: B, retrieve: bool, security_level: SecurityLevel) -> Result<Option<Vec<u8>>, FsError<String>> {
        if self.cid != static_hyper_ratchet.get_cid() {
            return Err(FsError::Generic("Invalid CID".to_string()));
        }

        static_hyper_ratchet.encrypt(bytes.as_ref()).and_then(|new_encrypted_bytes| {
            self.security_level_drilled = security_level;
            self.drill_version = static_hyper_ratchet.version();
            let _ = self.set_metadata(DATE_UPDATED, get_present_formatted_timestamp());
            if retrieve {
                let ret = self.data_encrypted_bytes.clone();
                self.data_encrypted_bytes = Some(new_encrypted_bytes);
                Ok(ret)
            } else {
                self.data_encrypted_bytes = Some(new_encrypted_bytes);
                Ok(None)
            }
        }).map_err(|err| FsError::Generic(err.to_string()))
    }

    /// Encrypts the data for the first-time within this HyxeFile. This returns an error if [1] the encryption fails, or; [2] if the CID of the
    /// drill supplied does not equal the CID associated with this HyxeFile.
    pub fn drill_contents<B: ByteSlice>(&mut self, static_hyper_ratchet: &HyperRatchet, bytes: B, security_level: SecurityLevel) -> Result<(), FsError<String>> {
        if self.cid != static_hyper_ratchet.get_cid() {
            return Err(FsError::Generic("Invalid CID".to_string()));
        }

        if let None = self.data_encrypted_bytes.borrow() {
            static_hyper_ratchet.encrypt(bytes.as_ref()).and_then(|new_encrypted_bytes| {
                self.data_encrypted_bytes = Some(new_encrypted_bytes);
                self.security_level_drilled = security_level;
                self.drill_version = static_hyper_ratchet.version();
                Ok(())
            }).map_err(|err| FsError::Generic(err.to_string()))
        } else {
            Err(FsError::Generic("You cannot drill the contents if there is data currently! Use redrill_contents instead".to_string()))
        }
    }

    /// Saves to a local random location specified by the user on init. This does not necessarily imply the file will be synchronized
    /// with the central server. If you with to necessarily imply the synchronization operation, use `save_vfs` instead.
    ///
    /// Panics if no data is loaded
    pub async fn save_locally(&self) -> Result<PathBuf, FsError<String>> where Self: AsyncIO {
        let real_file_path = get_pathbuf(format!("{}{}.{}", HYXE_VIRTUAL_DIR.lock().unwrap().as_ref().unwrap(), generate_random_string(HYXE_FILE_OBFUSCATED_LEN), HYXE_FILE_EXT));
        log::info!("[HyxeFile] Saving {} to {}", &self.file_name, real_file_path.to_str().unwrap());
        self.async_serialize_to_local_fs(&real_file_path).await
            .and_then(|_| {
                Ok(real_file_path)
            })
    }

    /// Saves the file without blocking
    pub fn save_locally_blocking(&self) -> Result<PathBuf, FsError<String>> where Self: SyncIO {
        let real_file_path = get_pathbuf(format!("{}{}.{}", HYXE_VIRTUAL_DIR.lock().unwrap().as_ref().unwrap(), generate_random_string(HYXE_FILE_OBFUSCATED_LEN), HYXE_FILE_EXT));
        log::info!("[HyxeFile] Saving {} to {}", &self.file_name, real_file_path.to_str().unwrap());
        SyncIO::serialize_to_local_fs(self, &real_file_path)
            .and_then(|_| Ok(real_file_path))
    }

    /// Decrypts the data, but does not mutate the underlying data type. This returns an error if [1] the encryption fails, or; [2] if the drill version
    /// supplied does not equal the current drill version applied to the bytes, or; [3] if the CID of the
    /// drill supplied does not equal the CID associated with this HyxeFile, or; [4] if there is no content currently
    /// drilled within the HyxeFile (i.e., `self.data_encrypted_bytes.is_none()`). The return type is a newly allocated vector. This should NOT be called
    /// multiple times in succession (it can if needed, however) because of performance reasons. Instead, you should read the data once, and then pass
    /// references to that data.
    pub fn read_contents(&self, static_hyper_ratchet: &HyperRatchet) -> Result<Vec<u8>, FsError<String>> {
        if self.cid != static_hyper_ratchet.get_cid() {
            return Err(FsError::Generic("Invalid CID".to_string()));
        }

        if self.drill_version != static_hyper_ratchet.version() {
            return Err(FsError::Generic("You must supply the correct drill version when reading the encrypted contents".to_string()));
        }

        if let Some(bytes) = self.data_encrypted_bytes.borrow() {
            static_hyper_ratchet.decrypt(bytes).and_then(|decrypted_bytes| {
                Ok(decrypted_bytes)
            }).map_err(|err| FsError::Generic(err.to_string()))
        } else {
            Err(FsError::Generic("You cannot redrill the contents if there are none currently! Use drill_contents instead".to_string()))
        }
    }

    /// Replaces the metadata table within. Possibly returns a pre-existing string of data
    pub fn set_metadata<S: ToString>(&mut self, metadata_flag: u8, information: S) -> Option<String> {
        self.metadata.insert(metadata_flag, information.to_string())
    }

    /// Possibly returns a metadata value
    pub fn get_metadata(&self, metadata_flag: u8) -> Option<&String> {
        self.metadata.get(&metadata_flag)
    }

    /// Renames the filename. This does NOT synchronize the information with the server
    pub fn rename<S: ToString>(&mut self, name: S) {
        self.file_name = name.to_string();
    }

    /// Returns the drill version used to drill-shut.
    /// Returns None if data is not currently drilled
    pub fn get_active_drill_version(&self) -> Option<u32> {
        match self.data_encrypted_bytes.as_ref() {
            Some(_) => Some(self.drill_version),
            None => None
        }
    }
}

/// Organizes the various types of metadata storable within any HyxeFile
pub mod metadata_flags {
    /// The author of the file
    pub const AUTHOR: u8 = 0;
    /// The date the HyxeFile was instantiated in memory (not the date pushed to the disk)
    pub const DATE_CREATED: u8 = 1;
    /// The date the information was re-encrypted
    pub const DATE_UPDATED: u8 = 2;
}