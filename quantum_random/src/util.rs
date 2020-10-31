/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use bincode::ErrorKind;

#[allow(unused_must_use)]
/// Serializes an entity to the disk
pub(crate) fn serialize_entity_to_disk<T: serde::Serialize>(full_path: String, entity: T) -> Result<(), Box<ErrorKind>> {
    let writer = BufWriter::new(File::create(sanitize_path(full_path)).unwrap());
    bincode::serialize_into(writer, &entity)
}

/// Deserialized an entity to the disk
pub(crate) fn deserialize_entity_from_disk<'de, T: serde::de::DeserializeOwned>(full_path: String) -> Result<T, Box<ErrorKind>> {
    let reader = BufReader::new(File::open(sanitize_path(full_path)).unwrap());
    bincode::config().deserialize_from(reader)
}

/// The default name for the default EntropyBank
pub(crate) static ENTROPY_BANK_DEFAULT_FILE: &str = "local_storage";

pub(crate) static HOME_DIR: &str = ".quantum_random";

/// Checks to see if the EntropyBank exists locally
pub(crate) fn entropy_file_exists() -> bool {
    File::open(sanitize_path(format!(
        "{}cfg/{}.entropy",
        get_home_dir(),
        ENTROPY_BANK_DEFAULT_FILE
    )))
        .is_ok()
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn sanitize_path(path: String) -> String {
    path.replace("\\", "")
}

#[cfg(any(target_os = "windows"))]
pub(crate) fn sanitize_path(path: String) -> String {
    path.replace("/", "\\")
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn get_home_dir() -> String {
    let p: Box<Path> = dirs_2::home_dir().unwrap().into_boxed_path();
    let j = p.to_str().unwrap();
    format!("{}/{}/", j, HOME_DIR)
}

#[cfg(any(target_os = "windows"))]
pub(crate) fn get_home_dir() -> String {
    let p: Box<Path> = dirs_2::home_dir().unwrap().into_boxed_path();
    let j = p.to_str().unwrap();
    format!("{}\\{}\\", j, HOME_DIR)
}

/// Default Error type for this crate
pub enum QuantumError {
    /// Generic Error
    Generic(String),
}

impl QuantumError {
    /// Conveniance method
    pub fn throw<U>(input: &str) -> Result<U, QuantumError> {
        Err(QuantumError::Generic(input.to_string()))
    }

    /// Conveniance method
    pub fn throw_string<U>(input: String) -> Result<U, QuantumError> {
        Err(QuantumError::Generic(input))
    }

    /// For converting into downstream error types
    pub fn to_string(self) -> String {
        match self {
            QuantumError::Generic(e) => e
        }
    }
}
