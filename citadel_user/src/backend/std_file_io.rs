//! Standard Filesystem I/O Implementation
//!
//! Implements [`FileIO`] using `tokio::fs` for standard filesystem operations.

use crate::backend::file_io::{AsyncStreamWriter, DirEntry, FileIO};
use crate::misc::AccountError;
use async_trait::async_trait;
use citadel_io::tokio;
use tokio::io::AsyncWriteExt;

/// Standard filesystem I/O using `tokio::fs`.
pub struct StdFileIO;

#[async_trait]
impl FileIO for StdFileIO {
    async fn create_dir_all(&self, path: &str) -> Result<(), AccountError> {
        tokio::fs::create_dir_all(path)
            .await
            .map_err(|err| AccountError::io(err.to_string()))
    }

    async fn write_file(&self, path: &str, data: &[u8]) -> Result<(), AccountError> {
        tokio::fs::write(path, data)
            .await
            .map_err(|err| AccountError::io(err.to_string()))
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>, AccountError> {
        tokio::fs::read(path)
            .await
            .map_err(|err| AccountError::io(err.to_string()))
    }

    async fn remove_file(&self, path: &str) -> Result<(), AccountError> {
        tokio::fs::remove_file(path)
            .await
            .map_err(|err| AccountError::io(err.to_string()))
    }

    async fn remove_dir_all(&self, path: &str) -> Result<(), AccountError> {
        tokio::fs::remove_dir_all(path)
            .await
            .map_err(|err| AccountError::io(err.to_string()))
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>, AccountError> {
        let mut entries = Vec::new();
        let mut dir = tokio::fs::read_dir(path)
            .await
            .map_err(|err| AccountError::io(err.to_string()))?;

        while let Some(entry) = dir
            .next_entry()
            .await
            .map_err(|err| AccountError::io(err.to_string()))?
        {
            let path_buf = entry.path();
            let is_file = path_buf.is_file();
            let extension = path_buf
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_string());
            let path_str = path_buf.to_string_lossy().to_string();
            entries.push(DirEntry {
                path: path_str,
                is_file,
                extension,
            });
        }

        Ok(entries)
    }

    async fn create_streaming_writer(
        &self,
        path: &str,
    ) -> Result<Box<dyn AsyncStreamWriter>, AccountError> {
        let file = tokio::fs::File::create(path)
            .await
            .map_err(|err| AccountError::io(err.to_string()))?;
        Ok(Box::new(StdStreamWriter {
            writer: tokio::io::BufWriter::new(file),
        }))
    }
}

struct StdStreamWriter {
    writer: tokio::io::BufWriter<tokio::fs::File>,
}

#[async_trait]
impl AsyncStreamWriter for StdStreamWriter {
    async fn write_chunk(&mut self, data: &[u8]) -> Result<(), AccountError> {
        self.writer
            .write_all(data)
            .await
            .map_err(|err| AccountError::io(err.to_string()))
    }

    async fn finish(mut self: Box<Self>) -> Result<(), AccountError> {
        self.writer
            .flush()
            .await
            .map_err(|err| AccountError::io(err.to_string()))?;
        self.writer
            .into_inner()
            .sync_all()
            .await
            .map_err(|err| AccountError::io(err.to_string()))
    }
}
