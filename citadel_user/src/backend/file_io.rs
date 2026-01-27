//! File I/O Abstraction Layer
//!
//! Provides async file I/O traits that abstract over different storage backends
//! (standard filesystem via tokio::fs, or OPFS for WASM environments).

use crate::misc::AccountError;
use async_trait::async_trait;

/// A directory entry returned by [`FileIO::read_dir`].
pub struct DirEntry {
    /// Full path string of the entry
    pub path: String,
    /// Whether this entry is a file (as opposed to a directory)
    pub is_file: bool,
    /// File extension, if any
    pub extension: Option<String>,
}

/// Async trait for streaming writes to a file.
#[async_trait]
pub trait AsyncStreamWriter: Send + Sync {
    /// Write a chunk of data to the file.
    async fn write_chunk(&mut self, data: &[u8]) -> Result<(), AccountError>;
    /// Flush and finalize the file.
    async fn finish(self: Box<Self>) -> Result<(), AccountError>;
}

/// Async file I/O abstraction. Implementations provide either standard filesystem
/// or OPFS-based storage.
#[async_trait]
pub trait FileIO: Send + Sync + 'static {
    /// Recursively create all directories in the given path.
    async fn create_dir_all(&self, path: &str) -> Result<(), AccountError>;
    /// Write `data` to the file at `path`, creating or overwriting it.
    async fn write_file(&self, path: &str, data: &[u8]) -> Result<(), AccountError>;
    /// Read the entire contents of the file at `path`.
    async fn read_file(&self, path: &str) -> Result<Vec<u8>, AccountError>;
    /// Remove the file at `path`.
    async fn remove_file(&self, path: &str) -> Result<(), AccountError>;
    /// Recursively remove the directory at `path` and all its contents.
    async fn remove_dir_all(&self, path: &str) -> Result<(), AccountError>;
    /// List entries in the directory at `path` (non-recursive).
    async fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>, AccountError>;
    /// Create a streaming writer for the file at `path`.
    async fn create_streaming_writer(
        &self,
        path: &str,
    ) -> Result<Box<dyn AsyncStreamWriter>, AccountError>;
}
