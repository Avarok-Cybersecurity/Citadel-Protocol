//! OPFS (Origin Private File System) I/O Implementation
//!
//! Implements [`FileIO`] using the `opfs` crate for browser-based persistent storage.

use crate::backend::file_io::{AsyncStreamWriter, DirEntry, FileIO};
use crate::misc::AccountError;
use async_trait::async_trait;
use opfs::persistent;
use opfs::{
    CreateWritableOptions, DirectoryEntry, DirectoryHandle, FileHandle, FileSystemRemoveOptions,
    GetDirectoryHandleOptions, GetFileHandleOptions, WritableFileStream, WriteParams,
};

/// OPFS-based file I/O using the `opfs` crate.
///
/// Paths are interpreted as `/`-separated segments navigated from the
/// app-specific root directory.
pub struct OpfsFileIO;

impl OpfsFileIO {
    /// Create a new `OpfsFileIO` instance.
    pub fn new() -> Self {
        Self
    }

    /// Navigate to the parent directory of `path`, returning the directory handle
    /// and the final segment (file or directory name).
    async fn navigate_to_parent(
        &self,
        path: &str,
    ) -> Result<(persistent::DirectoryHandle, String), AccountError> {
        let cleaned = path.trim_matches('/');
        let segments: Vec<&str> = cleaned.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return Err(AccountError::io("Empty path".into()));
        }

        let mut dir = persistent::app_specific_dir()
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))?;

        // Navigate to parent directory, creating intermediate dirs
        for segment in &segments[..segments.len() - 1] {
            dir = dir
                .get_directory_handle_with_options(
                    segment,
                    &GetDirectoryHandleOptions { create: true },
                )
                .await
                .map_err(|err| AccountError::io(format!("{err:?}")))?;
        }

        let name = segments.last().unwrap().to_string();
        Ok((dir, name))
    }

    /// Navigate to the directory at `path`, creating it if needed.
    async fn navigate_to_dir(
        &self,
        path: &str,
    ) -> Result<persistent::DirectoryHandle, AccountError> {
        let cleaned = path.trim_matches('/');
        let segments: Vec<&str> = cleaned.split('/').filter(|s| !s.is_empty()).collect();

        let mut dir = persistent::app_specific_dir()
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))?;

        for segment in &segments {
            dir = dir
                .get_directory_handle_with_options(
                    segment,
                    &GetDirectoryHandleOptions { create: true },
                )
                .await
                .map_err(|err| AccountError::io(format!("{err:?}")))?;
        }

        Ok(dir)
    }
}

#[async_trait]
impl FileIO for OpfsFileIO {
    async fn create_dir_all(&self, path: &str) -> Result<(), AccountError> {
        let _ = self.navigate_to_dir(path).await?;
        Ok(())
    }

    async fn write_file(&self, path: &str, data: &[u8]) -> Result<(), AccountError> {
        let (dir, name) = self.navigate_to_parent(path).await?;
        let mut file_handle = dir
            .get_file_handle_with_options(&name, &GetFileHandleOptions { create: true })
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))?;

        let mut writable = file_handle
            .create_writable_with_options(&CreateWritableOptions::default())
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))?;

        writable
            .write(&WriteParams::from(data.to_vec()))
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))?;

        writable
            .close()
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))?;

        Ok(())
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>, AccountError> {
        let (dir, name) = self.navigate_to_parent(path).await?;
        let file_handle = dir
            .get_file_handle_with_options(&name, &GetFileHandleOptions { create: false })
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))?;

        file_handle
            .read()
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))
    }

    async fn remove_file(&self, path: &str) -> Result<(), AccountError> {
        let (dir, name) = self.navigate_to_parent(path).await?;
        dir.remove_entry(&name)
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))
    }

    async fn remove_dir_all(&self, path: &str) -> Result<(), AccountError> {
        let (dir, name) = self.navigate_to_parent(path).await?;
        dir.remove_entry_with_options(&name, &FileSystemRemoveOptions { recursive: true })
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>, AccountError> {
        use futures::StreamExt;

        let dir = self.navigate_to_dir(path).await?;
        let mut entries_stream = dir.entries();
        let mut result = Vec::new();

        while let Some(entry) = entries_stream.next().await {
            let (name, dir_entry) =
                entry.map_err(|err| AccountError::io(format!("{err:?}")))?;
            let full_path = format!("{}/{}", path.trim_end_matches('/'), name);
            let is_file = matches!(dir_entry, DirectoryEntry::File(_));
            let extension = if is_file {
                name.rsplit('.').next().map(|s| s.to_string())
            } else {
                None
            };
            result.push(DirEntry {
                path: full_path,
                is_file,
                extension,
            });
        }

        Ok(result)
    }

    async fn create_streaming_writer(
        &self,
        path: &str,
    ) -> Result<Box<dyn AsyncStreamWriter>, AccountError> {
        let (dir, name) = self.navigate_to_parent(path).await?;
        let mut file_handle = dir
            .get_file_handle_with_options(&name, &GetFileHandleOptions { create: true })
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))?;

        let writable = file_handle
            .create_writable_with_options(&CreateWritableOptions::default())
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))?;

        Ok(Box::new(OpfsStreamWriter { writable }))
    }
}

struct OpfsStreamWriter {
    writable: persistent::WritableFileStream,
}

// OPFS is single-threaded in WASM, but the trait requires Send+Sync.
// The persistent types from the opfs crate handle this correctly on native
// (tokio::fs) and on web (single-threaded).
unsafe impl Send for OpfsStreamWriter {}
unsafe impl Sync for OpfsStreamWriter {}

#[async_trait]
impl AsyncStreamWriter for OpfsStreamWriter {
    async fn write_chunk(&mut self, data: &[u8]) -> Result<(), AccountError> {
        self.writable
            .write(&WriteParams::from(data.to_vec()))
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))
    }

    async fn finish(self: Box<Self>) -> Result<(), AccountError> {
        self.writable
            .close()
            .await
            .map_err(|err| AccountError::io(format!("{err:?}")))
    }
}
