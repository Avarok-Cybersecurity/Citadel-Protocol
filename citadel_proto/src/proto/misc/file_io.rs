//! File I/O Abstraction
//!
//! Provides standalone functions that abstract file operations with
//! platform-specific dispatch via `cfg`. Native targets perform real file I/O;
//! WASM targets return stubs/no-ops.
//!
//! All cfg-gates for file I/O are concentrated in this module so the
//! protocol layer (session, packet processors) remains platform-agnostic.

use crate::error::NetworkError;
use citadel_types::proto::VirtualObjectMetadata;
use std::path::{Path, PathBuf};

/// Open a file and validate it for transfer.
///
/// On native: opens the file, validates its length against expected metadata,
/// and returns the file's `std::fs::Metadata`.
///
/// On WASM: returns an error (file transfer not supported).
pub(crate) fn open_and_validate_for_transfer(
    source_path: &Path,
    expected_metadata: Option<&VirtualObjectMetadata>,
) -> Result<std::fs::Metadata, NetworkError> {
    #[cfg(not(target_family = "wasm"))]
    {
        use citadel_crypt::prelude::FixedSizedSource;

        let file = std::fs::File::open(source_path)
            .map_err(|err: std::io::Error| NetworkError::Generic(err.to_string()))?;

        if let Some(virtual_object_metadata) = expected_metadata {
            let expected_min_length = virtual_object_metadata.plaintext_length;
            let file_length = file
                .length()
                .map_err(|err| NetworkError::Generic(err.to_string()))?;
            if file_length < expected_min_length as u64 {
                log::warn!(target: "citadel", "The REVFS file cannot be pulled since it has not yet synchronized with the filesystem: Current file length: {file_length}, expected min length: {expected_min_length}");
                return Err(NetworkError::InternalError(
                    "The REVFS file cannot be pulled since it has not yet synchronized with the filesystem",
                ));
            }
        }

        file.metadata()
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    #[cfg(target_family = "wasm")]
    {
        let _ = (source_path, expected_metadata);
        Err(NetworkError::InternalError(
            "File transfer not yet supported on WASM",
        ))
    }
}

/// Asynchronously delete a file after transfer.
///
/// On native: spawns an async task to remove the file.
/// On WASM: no-op.
pub(crate) fn async_delete_file(source: PathBuf) {
    #[cfg(not(target_family = "wasm"))]
    {
        spawn!(citadel_io::tokio::fs::remove_file(source));
    }

    #[cfg(target_family = "wasm")]
    {
        let _ = source;
    }
}
