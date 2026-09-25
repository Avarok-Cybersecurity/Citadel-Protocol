//! Reading and deleting stored RE-VFS objects, and the key both sides use (see `revfs` for how
//! objects are written).

use super::{
    cid_value, op_error, read_blob, read_integer, read_text, schema, text_value, HostSqlBackend,
    SqlStatement, SqlValue,
};
use crate::misc::{prepare_virtual_path, validate_virtual_path, AccountError};
use crate::serialization::SyncIO;
use citadel_crypt::misc::CryptError;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::scramble::streaming_crypt_scrambler::{
    BytesSource, FixedSizedSource, ObjectSource,
};
use citadel_io::ErrorCode;
use citadel_types::proto::VirtualObjectMetadata;
use std::path::{Path, PathBuf};

/// Where an object lives: its owner and its normalized virtual path.
pub(super) struct ObjectKey {
    pub(super) cid: u64,
    pub(super) path: String,
}

impl ObjectKey {
    pub(super) fn new(cid: u64, virtual_path: &Path) -> Result<Self, AccountError> {
        let virtual_path = prepare_virtual_path(virtual_path);
        validate_virtual_path(&virtual_path)?;
        Ok(Self {
            cid,
            path: virtual_path.display().to_string(),
        })
    }

    pub(super) fn params(&self) -> Vec<SqlValue> {
        vec![cid_value(self.cid), text_value(self.path.clone())]
    }
}

impl<R: Ratchet, Fcm: Ratchet> HostSqlBackend<R, Fcm> {
    /// The stored object and the metadata it was uploaded with. The source holds the whole
    /// object: `ObjectSource` is read synchronously and this host answers asynchronously, so it
    /// cannot be read lazily. It is read one chunk row per host call, from one upload's rows, so
    /// a replacement committed part way through is detected instead of spliced.
    pub(super) async fn load_object(
        &self,
        cid: u64,
        virtual_path: &Path,
    ) -> Result<(Box<dyn ObjectSource>, VirtualObjectMetadata), AccountError> {
        let key = ObjectKey::new(cid, virtual_path)?;
        let row = self
            .query(schema::SELECT_REVFS_FILE, key.params())
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| citadel_io::error!(ErrorCode::RevfsFileNotFound, key.path.clone()))?;
        let upload = read_text(&row, 0)?;
        let size = usize::try_from(read_integer(&row, 1)?)
            .map_err(|_| op_error("stored object size out of range"))?;
        let chunks = read_integer(&row, 2)?;
        let group_bytes = usize::try_from(read_integer(&row, 3)?)
            .map_err(|_| op_error("stored group size out of range"))?;
        let metadata = VirtualObjectMetadata::deserialize_from_owned_vector(read_blob(row, 4)?)?;

        let changed = || citadel_io::error!(ErrorCode::RevfsChangedDuringRead, key.path.clone());
        let mut bytes = Vec::with_capacity(size);
        for idx in 0..chunks {
            let row = self
                .query(
                    schema::SELECT_REVFS_CHUNK,
                    vec![text_value(upload.clone()), SqlValue::Integer(idx)],
                )
                .await?
                .into_iter()
                .next()
                .ok_or_else(changed)?;
            bytes.extend_from_slice(&read_blob(row, 0)?);
        }
        if bytes.len() != size {
            return Err(changed());
        }
        let source = StoredObject {
            bytes: BytesSource::from(bytes),
            group_bytes,
        };
        Ok((Box::new(source), metadata))
    }

    pub(super) async fn delete_object(
        &self,
        cid: u64,
        virtual_path: &Path,
    ) -> Result<(), AccountError> {
        let key = ObjectKey::new(cid, virtual_path)?;
        let results = self
            .run(vec![
                SqlStatement {
                    sql: schema::DELETE_REVFS_FILE_CHUNKS,
                    params: key.params(),
                },
                SqlStatement {
                    sql: schema::DELETE_REVFS_FILE,
                    params: key.params(),
                },
            ])
            .await?;
        if results[1].is_empty() {
            return Err(citadel_io::error!(ErrorCode::RevfsFileNotFound, key.path));
        }
        Ok(())
    }
}

/// A stored object on its way back to its owner: its bytes, and the size of the groups it must
/// be sent in, which are the groups its owner encrypted it in.
struct StoredObject {
    bytes: BytesSource,
    group_bytes: usize,
}

impl ObjectSource for StoredObject {
    fn try_get_stream(&mut self) -> Result<Box<dyn FixedSizedSource>, CryptError> {
        self.bytes.try_get_stream()
    }

    fn get_source_name(&self) -> Result<String, CryptError> {
        self.bytes.get_source_name()
    }

    fn path(&self) -> Option<PathBuf> {
        None
    }

    fn required_group_size(&self) -> Option<usize> {
        Some(self.group_bytes)
    }
}
