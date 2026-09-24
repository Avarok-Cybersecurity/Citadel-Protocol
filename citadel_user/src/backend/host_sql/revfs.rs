//! RE-VFS objects: the bytes a client encrypted locally and asked this node to keep, stored as
//! bounded rows so neither a write nor a read of the store grows with the size of the file.
//!
//! An upload stages its chunks under an id of its own and swaps in with one transaction at the
//! end, so a reader sees the old object or the new one and never a mix, and an upload that fails
//! or is cut short leaves the previous object untouched. Keys mirror the file backend's: the
//! uploader's CID and the virtual path as `prepare_virtual_path` normalizes it.

use super::revfs_read::ObjectKey;
use super::{
    op_error, read_integer, schema, text_value, HostSqlBackend, SqlStatement, SqlValue,
    StorageQuota,
};
use crate::misc::AccountError;
use crate::serialization::SyncIO;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use citadel_io::ErrorCode;
use citadel_types::proto::{ObjectTransferStatus, TransferType, VirtualObjectMetadata};
use std::path::PathBuf;

/// The largest chunk row. A received group can be several MB (the scrambler's default group is
/// 3 MB) and a Durable Object's SQLite refuses any value over 2 MB, so groups are split.
pub const REVFS_CHUNK_BYTES: usize = 512 * 1024;

/// What an upload wrote before it committed.
struct Staged {
    groups: usize,
    first_group_bytes: usize,
    chunks: i64,
    bytes: u64,
}

impl<R: Ratchet, Fcm: Ratchet> HostSqlBackend<R, Fcm> {
    /// Stores the object `source` streams, one received group at a time.
    pub(super) async fn store_object(
        &self,
        source: UnboundedReceiver<Vec<u8>>,
        sink_metadata: &VirtualObjectMetadata,
        status_tx: UnboundedSender<ObjectTransferStatus>,
    ) -> Result<(), AccountError> {
        let virtual_path = match &sink_metadata.transfer_type {
            TransferType::RemoteEncryptedVirtualFilesystem { virtual_path, .. } => virtual_path,
            // Nothing could read such a file back: the file backend hands its kernel a path on
            // disk, and this backend has none. Refused, rather than accepted and discarded.
            TransferType::FileTransfer => {
                return Err(citadel_io::error!(
                    ErrorCode::HostSqlPlainFileTransferUnsupported
                ))
            }
        };
        let key = ObjectKey::new(sink_metadata.cid, virtual_path)?;
        let quota = self.storage_quota()?;

        // The declared length is only a floor on what will arrive (the chunks carry the client's
        // own encryption on top), so this refuses the hopeless upload early; the per-chunk check
        // in `stage_chunk` is what enforces the quota.
        if let StorageQuota::Bytes(limit) = quota {
            let declared = sink_metadata.plaintext_length as u64;
            if self.usage_except(&key).await?.saturating_add(declared) > limit {
                return Err(storage_full(limit));
            }
        }

        let upload = format!("{:032x}", rand::random::<u128>());
        let mut params = vec![text_value(upload.clone())];
        params.extend(key.params());
        let _ = self.query(schema::INSERT_REVFS_UPLOAD, params).await?;
        let _ = status_tx.send(ObjectTransferStatus::ReceptionBeginning(
            PathBuf::from(&key.path),
            sink_metadata.clone(),
        ));

        let outcome = self
            .stage_and_commit(source, sink_metadata, &key, &upload, quota)
            .await;
        if outcome.is_err() {
            // Best effort: a node that cannot reach its storage now discards the staged rows at
            // its next start (schema::DISCARD_ABANDONED_UPLOADS).
            if let Err(err) = self.discard_upload(&upload).await {
                log::error!(target: "citadel", "Unable to discard failed RE-VFS upload {upload}: {err}");
            }
        }
        outcome
    }

    async fn stage_and_commit(
        &self,
        mut source: UnboundedReceiver<Vec<u8>>,
        sink_metadata: &VirtualObjectMetadata,
        key: &ObjectKey,
        upload: &str,
        quota: StorageQuota,
    ) -> Result<(), AccountError> {
        let mut staged = Staged {
            groups: 0,
            first_group_bytes: 0,
            chunks: 0,
            bytes: 0,
        };
        while let Some(group) = source.recv().await {
            if staged.groups == 0 {
                staged.first_group_bytes = group.len();
            }
            staged.groups += 1;
            for piece in group.chunks(REVFS_CHUNK_BYTES) {
                self.stage_chunk(key, upload, staged.chunks, piece, quota)
                    .await?;
                staged.chunks += 1;
                staged.bytes += piece.len() as u64;
            }
        }
        // The stream also closes when a transfer is abandoned part way; committing then would
        // replace a whole object with the front of another.
        if staged.groups != sink_metadata.group_count {
            return Err(citadel_io::error!(
                ErrorCode::RevfsUploadIncomplete,
                staged.groups,
                sink_metadata.group_count
            ));
        }
        self.commit(key, upload, &staged, sink_metadata.serialize_to_vector()?)
            .await?;
        log::info!(target: "citadel", "Stored RE-VFS object {} for {}: {} bytes in {} chunks", key.path, key.cid, staged.bytes, staged.chunks);
        Ok(())
    }

    async fn stage_chunk(
        &self,
        key: &ObjectKey,
        upload: &str,
        idx: i64,
        piece: &[u8],
        quota: StorageQuota,
    ) -> Result<(), AccountError> {
        let len = SqlValue::Integer(piece.len() as i64);
        let mut insert_params = vec![
            text_value(upload),
            SqlValue::Integer(idx),
            SqlValue::Blob(piece.to_vec()),
        ];
        let insert_sql = match quota {
            StorageQuota::Unlimited => schema::INSERT_REVFS_CHUNK,
            StorageQuota::Bytes(limit) => {
                insert_params.extend(key.params());
                insert_params.push(len.clone());
                insert_params.push(SqlValue::Integer(i64::try_from(limit).map_err(|_| {
                    op_error(format!("storage quota {limit} does not fit a SQL integer"))
                })?));
                schema::INSERT_REVFS_CHUNK_WITHIN_QUOTA
            }
        };
        let results = self
            .run(vec![
                SqlStatement {
                    sql: insert_sql,
                    params: insert_params,
                },
                SqlStatement {
                    sql: schema::ADD_REVFS_UPLOAD_BYTES,
                    params: vec![
                        len,
                        text_value(upload),
                        text_value(upload),
                        SqlValue::Integer(idx),
                    ],
                },
            ])
            .await?;
        match (results[0].is_empty(), quota) {
            (false, _) => Ok(()),
            (true, StorageQuota::Bytes(limit)) => Err(storage_full(limit)),
            (true, StorageQuota::Unlimited) => Err(op_error(
                "the host stored no row for an unconditional insert",
            )),
        }
    }

    async fn commit(
        &self,
        key: &ObjectKey,
        upload: &str,
        staged: &Staged,
        metadata: Vec<u8>,
    ) -> Result<(), AccountError> {
        let mut replaced = key.params();
        replaced.push(text_value(upload));
        let mut file = key.params();
        file.extend([
            text_value(upload),
            SqlValue::Integer(
                i64::try_from(staged.bytes)
                    .map_err(|_| op_error(format!("object of {} bytes", staged.bytes)))?,
            ),
            SqlValue::Integer(staged.chunks),
            SqlValue::Integer(staged.first_group_bytes as i64),
            SqlValue::Blob(metadata),
            text_value(upload),
        ]);
        let results = self
            .run(vec![
                SqlStatement {
                    sql: schema::DELETE_REPLACED_REVFS_CHUNKS,
                    params: replaced,
                },
                SqlStatement {
                    sql: schema::UPSERT_REVFS_FILE,
                    params: file,
                },
                SqlStatement {
                    sql: schema::DELETE_REVFS_UPLOAD,
                    params: vec![text_value(upload)],
                },
            ])
            .await?;
        if results[2].is_empty() {
            return Err(citadel_io::error!(
                ErrorCode::RevfsUploadVanished,
                key.path.clone()
            ));
        }
        Ok(())
    }

    async fn discard_upload(&self, upload: &str) -> Result<(), AccountError> {
        let statement = |sql| SqlStatement {
            sql,
            params: vec![text_value(upload)],
        };
        self.run(vec![
            statement(schema::DELETE_REVFS_UPLOAD_CHUNKS),
            statement(schema::DELETE_REVFS_UPLOAD),
        ])
        .await
        .map(|_| ())
    }

    /// Bytes held or staging, not counting the object at `key` (the upload asking replaces it).
    async fn usage_except(&self, key: &ObjectKey) -> Result<u64, AccountError> {
        let rows = self
            .query(schema::SELECT_REVFS_USAGE_EXCEPT, key.params())
            .await?;
        let used = rows
            .first()
            .map(|row| read_integer(row, 0))
            .transpose()?
            .unwrap_or(0);
        u64::try_from(used).map_err(|_| op_error(format!("negative storage usage {used}")))
    }
}

fn storage_full(limit: u64) -> AccountError {
    citadel_io::error!(ErrorCode::RevfsStorageFull, limit)
}
