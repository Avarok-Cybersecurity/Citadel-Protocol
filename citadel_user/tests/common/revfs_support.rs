//! Shared by the host_sql RE-VFS suites: a host that can be made to refuse chunk writes, and
//! helpers that stream an object in and read it back the way the protocol does.
#![allow(dead_code)] // each suite uses its own subset

use crate::sqlite_host::SqliteHost;
use async_trait::async_trait;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio::sync::mpsc::unbounded_channel;
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::{ObjectId, ObjectTransferStatus, TransferType, VirtualObjectMetadata};
use citadel_user::backend::host_sql::{
    HostSqlBackend, HostSqlHandle, SqlHost, SqlRow, SqlStatement, SqlValue, StorageQuota,
};
use citadel_user::backend::BackendConnection;
use citadel_user::misc::AccountError;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub type Backend = HostSqlBackend<StackedRatchet, StackedRatchet>;
pub const CID: u64 = 4242;
pub const KIB: usize = 1024;
pub const CHUNKS: &str = "SELECT COUNT(*) FROM citadel_revfs_chunks";
pub const FILES: &str = "SELECT COUNT(*) FROM citadel_revfs_files";
pub const UPLOADS: &str = "SELECT COUNT(*) FROM citadel_revfs_uploads";

/// A SQLite host that, once armed, refuses every chunk write, as a full or failing disk would.
pub struct RefusingHost {
    inner: SqliteHost,
    armed: Arc<AtomicBool>,
}

impl RefusingHost {
    pub fn handle(quota: StorageQuota) -> (HostSqlHandle, Arc<AtomicBool>) {
        let armed = Arc::new(AtomicBool::new(false));
        let host = Self {
            inner: SqliteHost::in_memory(quota),
            armed: armed.clone(),
        };
        (HostSqlHandle::new(host), armed)
    }
}

#[async_trait]
impl SqlHost for RefusingHost {
    async fn execute(&self, statements: Vec<SqlStatement>) -> Result<Vec<Vec<SqlRow>>, String> {
        let chunk_write = |s: &SqlStatement| s.sql.starts_with("INSERT INTO citadel_revfs_chunks");
        if self.armed.load(Ordering::SeqCst) && statements.iter().any(chunk_write) {
            return Err("the host refused the write".into());
        }
        self.inner.execute(statements).await
    }

    fn storage_quota(&self) -> Result<StorageQuota, String> {
        self.inner.storage_quota()
    }
}

pub async fn connected(host: &HostSqlHandle) -> Backend {
    let mut backend = Backend::new(host.clone());
    BackendConnection::<StackedRatchet, StackedRatchet>::connect(&mut backend)
        .await
        .unwrap();
    backend
}

pub fn bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

pub fn metadata(path: &str, groups: &[Vec<u8>]) -> VirtualObjectMetadata {
    VirtualObjectMetadata {
        name: "object.bin".into(),
        date_created: String::new(),
        author: CID.to_string(),
        plaintext_length: groups.iter().map(Vec::len).sum(),
        group_count: groups.len(),
        object_id: ObjectId::random(),
        cid: CID,
        transfer_type: TransferType::RemoteEncryptedVirtualFilesystem {
            virtual_path: PathBuf::from(path),
            security_level: SecurityLevel::Reinforced,
        },
    }
}

/// Streams `groups` as the protocol would, closing the stream after them, and returns the
/// backend's answer and every status it reported.
pub async fn upload(
    backend: &Backend,
    meta: &VirtualObjectMetadata,
    groups: &[Vec<u8>],
) -> (Result<(), AccountError>, Vec<ObjectTransferStatus>) {
    let (tx, rx) = unbounded_channel();
    for group in groups {
        tx.send(group.clone()).unwrap();
    }
    drop(tx);
    let (status_tx, mut status_rx) = unbounded_channel();
    let result = backend.stream_object_to_backend(rx, meta, status_tx).await;
    let mut statuses = Vec::new();
    while let Ok(status) = status_rx.try_recv() {
        statuses.push(status);
    }
    (result, statuses)
}

pub async fn store(backend: &Backend, path: &str, groups: &[Vec<u8>]) -> Result<(), AccountError> {
    upload(backend, &metadata(path, groups), groups).await.0
}

pub async fn read_back(backend: &Backend, path: &str) -> Result<Vec<u8>, AccountError> {
    let (mut source, _) = backend.revfs_get_file_info(CID, path.into()).await?;
    let mut out = Vec::new();
    let _ = source
        .try_get_stream()
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    Ok(out)
}

pub async fn sql(host: &HostSqlHandle, sql: &'static str, params: Vec<SqlValue>) -> Vec<SqlRow> {
    host.0
        .execute(vec![SqlStatement { sql, params }])
        .await
        .unwrap()
        .remove(0)
}

pub async fn rows(host: &HostSqlHandle, count_query: &'static str) -> i64 {
    match sql(host, count_query, vec![]).await[0][0] {
        SqlValue::Integer(n) => n,
        ref other => panic!("count was {other:?}"),
    }
}
