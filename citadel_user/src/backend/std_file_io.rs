//! Standard Filesystem I/O Implementation
//!
//! Implements [`FileIO`] using `tokio::fs` for standard filesystem operations.

use crate::backend::file_io::{AsyncStreamWriter, DirEntry, FileIO};
use crate::misc::AccountError;
use async_trait::async_trait;
use citadel_io::tokio;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncWriteExt;

/// Rename `from` over `to`, retrying briefly on Windows.
///
/// POSIX replaces the destination even while a reader holds it open. Windows
/// does not: `MoveFileEx` fails with a sharing violation if another handle is
/// open without `FILE_SHARE_DELETE`, and Rust's `File::open` does not request
/// it. Reads of the account file are short, so a few retries cover the overlap;
/// without them this change would turn a torn read into a failed write on
/// Windows, which is not a trade worth making.
#[cfg(windows)]
async fn rename_replacing(from: &str, to: &str) -> std::io::Result<()> {
    const ATTEMPTS: usize = 5;
    let mut last = None;
    for attempt in 0..ATTEMPTS {
        match tokio::fs::rename(from, to).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last = Some(err);
                if attempt + 1 < ATTEMPTS {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    }
    Err(last.expect("the loop runs at least once"))
}

#[cfg(not(windows))]
async fn rename_replacing(from: &str, to: &str) -> std::io::Result<()> {
    tokio::fs::rename(from, to).await
}

/// Standard filesystem I/O using `tokio::fs`.
pub struct StdFileIO;

#[async_trait]
impl FileIO for StdFileIO {
    async fn create_dir_all(&self, path: &str) -> Result<(), AccountError> {
        tokio::fs::create_dir_all(path)
            .await
            .map_err(|err| AccountError::io(err.to_string()))
    }

    /// Write via a sibling temp file and a rename, so the destination is never
    /// observed half-written.
    ///
    /// `tokio::fs::write` truncates and then writes. The account file it is
    /// asked to write here is the whole `ClientNetworkAccount` — ratchet state
    /// and every stored key — and it is rewritten on every byte-map mutation,
    /// so the truncated window is not rare: a crash inside it leaves a file that
    /// `bincode::deserialize` cannot read, and the loader logs the failure and
    /// carries on without the account. A rename over an existing path is atomic
    /// on POSIX and on Windows via `MoveFileEx`, so a reader sees either the old
    /// bytes or the new ones.
    ///
    /// The temp name carries the process id and a counter because two writers
    /// may target one path — `save_cnac_by_cid` can run concurrently for the
    /// same CID. A shared temp name would let them interleave INTO the temp
    /// file, which is worse than the torn write this replaces. Distinct names
    /// keep the outcome last-writer-wins, which is what it already was.
    ///
    /// Deliberately no `fsync`: it would make the destination survive a machine
    /// crash, at the cost of a device flush on a path that is already too hot —
    /// the same write amplification this change exists to reduce. Atomicity of
    /// the replacement is the property that was missing; durability was never
    /// offered here, since the previous implementation did not sync either.
    async fn write_file(&self, path: &str, data: &[u8]) -> Result<(), AccountError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        // A sibling, so the rename stays within one filesystem — across a mount
        // boundary `rename` fails with EXDEV rather than being atomic. The
        // suffix keeps the extension off the one the account loader filters on,
        // so a temp file left behind by a crash is never mistaken for an
        // account.
        let temp = format!(
            "{path}.{}-{}.cnactmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );

        if let Err(err) = tokio::fs::write(&temp, data).await {
            // Best effort: the temp file may not exist, and the write error is
            // what the caller needs to see either way.
            let _ = tokio::fs::remove_file(&temp).await;
            return Err(AccountError::io(err.to_string()));
        }

        if let Err(err) = rename_replacing(&temp, path).await {
            let _ = tokio::fs::remove_file(&temp).await;
            return Err(AccountError::io(err.to_string()));
        }

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::file_io::FileIO;

    /// One writer's payload, self-identifying so a mixture of two is detectable.
    fn payload(marker: u8, len: usize) -> Vec<u8> {
        vec![marker; len]
    }

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "citadel-std-file-io-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A reader must never observe a half-written file.
    ///
    /// `tokio::fs::write` truncates and then writes, so a reader that lands in
    /// that window sees a short file — and the account file it writes is bincode,
    /// which a short read cannot deserialise. The payloads here are two different
    /// lengths of two different bytes, so any observation that is neither one
    /// nor the other is a torn read.
    ///
    /// Unix only. On Windows a reader holding the file open can make the rename
    /// fail outright rather than tear (see `rename_replacing`), so the same race
    /// measures a different property there and the retry window would make it
    /// timing-dependent.
    #[cfg(unix)]
    #[citadel_io::tokio::test]
    async fn a_concurrent_reader_never_sees_a_partial_write() {
        let dir = temp_dir();
        let path = dir.join("account.hca");
        let path_str = path.to_string_lossy().to_string();
        let io = StdFileIO;

        let short = payload(b'a', 4_096);
        let long = payload(b'b', 262_144);
        io.write_file(&path_str, &long).await.unwrap();

        let reader_path = path.clone();
        let reader = citadel_io::tokio::task::spawn_blocking(move || {
            let mut torn = Vec::new();
            for _ in 0..2_000 {
                if let Ok(seen) = std::fs::read(&reader_path) {
                    let complete = seen.iter().all(|b| *b == b'a') && seen.len() == 4_096
                        || seen.iter().all(|b| *b == b'b') && seen.len() == 262_144;
                    if !complete {
                        torn.push(seen.len());
                    }
                }
            }
            torn
        });

        for i in 0..200 {
            let data = if i % 2 == 0 { &short } else { &long };
            io.write_file(&path_str, data).await.unwrap();
        }

        let torn = reader.await.unwrap();
        assert!(
            torn.is_empty(),
            "the reader saw {} partial file(s), lengths {:?}",
            torn.len(),
            &torn[..torn.len().min(8)]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The temp file is an implementation detail and must not outlive the write
    /// — a leftover would accumulate one file per write, and the account loader
    /// scans this directory.
    ///
    /// Not a control for the defect: the previous implementation created no temp
    /// file at all, so it satisfies this trivially. It guards the new
    /// implementation's own hygiene, which is a different thing.
    #[citadel_io::tokio::test]
    async fn no_temp_file_survives_a_write() {
        let dir = temp_dir();
        let path = dir.join("account.hca");
        let io = StdFileIO;

        for _ in 0..5 {
            io.write_file(&path.to_string_lossy(), b"contents")
                .await
                .unwrap();
        }

        let left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|name| name != "account.hca")
            .collect();
        assert!(left.is_empty(), "temp files left behind: {left:?}");
        assert_eq!(std::fs::read(&path).unwrap(), b"contents");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed write must leave the previous contents readable rather than an
    /// empty or truncated file: the destination is only touched by the rename,
    /// which never runs.
    ///
    /// Also not a control — this particular failure (an unwritable path) never
    /// reached the destination under the old implementation either. The failure
    /// mode it could not survive was a crash MID-write, which no test can stage
    /// in-process; `a_concurrent_reader_never_sees_a_partial_write` is the one
    /// that discriminates.
    #[citadel_io::tokio::test]
    async fn a_failed_write_leaves_the_previous_contents() {
        let dir = temp_dir();
        let path = dir.join("account.hca");
        let path_str = path.to_string_lossy().to_string();
        let io = StdFileIO;

        io.write_file(&path_str, b"original").await.unwrap();

        // A path whose parent does not exist: the temp write fails, so the
        // rename never happens.
        let unwritable = dir.join("missing-dir").join("account.hca");
        assert!(io
            .write_file(&unwritable.to_string_lossy(), b"replacement")
            .await
            .is_err());

        assert_eq!(std::fs::read(&path).unwrap(), b"original");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
