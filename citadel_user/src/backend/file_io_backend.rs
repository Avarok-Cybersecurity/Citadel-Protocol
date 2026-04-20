//! # File I/O Backend
//!
//! A backend implementation that stores client data via the [`FileIO`] abstraction
//! while maintaining an in-memory cache for fast access. This supports both standard
//! filesystem and OPFS persistence through the same code path.

use crate::account_loader::load_cnac_files;
use crate::backend::file_io::FileIO;
use crate::backend::memory::{ByteMapDest, MemoryBackend};
use crate::backend::BackendConnection;
use crate::client_account::ClientNetworkAccount;
use crate::directory_store::DirectoryStore;
use crate::misc::{AccountError, CNACMetadata};
use crate::prelude::CNAC_SERIALIZED_EXTENSION;
use crate::serialization::SyncIO;
use async_trait::async_trait;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::scramble::streaming_crypt_scrambler::ObjectSource;
use citadel_io::tokio;
use citadel_io::tokio_stream::StreamExt;
use citadel_types::proto::{ObjectTransferStatus, TransferType, VirtualObjectMetadata};
use citadel_types::user::MutualPeer;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// A backend implementation that stores client data via the [`FileIO`] abstraction
/// while maintaining an in-memory cache for fast access.
pub struct FileIOBackend<R: Ratchet, Fcm: Ratchet> {
    memory_backend: MemoryBackend<R, Fcm>,
    directory_store: Option<DirectoryStore>,
    home_dir: String,
    file_io: Arc<dyn FileIO>,
}

impl<R: Ratchet, Fcm: Ratchet> FileIOBackend<R, Fcm> {
    /// Creates a new `FileIOBackend` with the given home directory and file I/O implementation.
    pub fn new(home_dir: String, file_io: Arc<dyn FileIO>) -> Self {
        Self {
            home_dir,
            memory_backend: MemoryBackend::default(),
            directory_store: None,
            file_io,
        }
    }
}

#[async_trait]
impl<R: Ratchet, Fcm: Ratchet> BackendConnection<R, Fcm> for FileIOBackend<R, Fcm> {
    async fn connect(&mut self) -> Result<(), AccountError> {
        let directory_store =
            crate::directory_store::setup_directories(self.home_dir.clone(), self.file_io.as_ref())
                .await?;
        let map = load_cnac_files(&directory_store, self.file_io.as_ref()).await?;
        *self.memory_backend.clients.get_mut() = map;

        // Load global KV store from disk if it exists. A read failure is
        // treated as "file absent" (first start), but a successful read with a
        // failed deserialize is treated as corruption and refuses startup.
        // Unlike per-CNAC files (where one bad file only loses one account),
        // a corrupt `global_kv.bin` would lose ALL server-global state — and
        // the next mutating call would silently overwrite the corrupt file
        // with an empty map. Fail loudly so the operator can investigate
        // (and, if the data is unrecoverable, manually delete the file).
        let global_kv_path = format!("{}global_kv.bin", directory_store.server_dir);
        if let Ok(data) = self.file_io.read_file(&global_kv_path).await {
            match bincode::deserialize(&data) {
                Ok(kv) => {
                    *self.memory_backend.global_kv.write() = kv;
                    log::info!(target: "citadel", "Loaded global KV store from {global_kv_path}");
                }
                Err(e) => {
                    return Err(AccountError::Generic(format!(
                        "global_kv.bin at {global_kv_path} exists but could not be \
                         deserialized: {e}. Refusing to overwrite — delete the file \
                         manually if the data is no longer needed."
                    )));
                }
            }
        }

        self.directory_store = Some(directory_store);
        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError> {
        Ok(true)
    }

    #[allow(unused_results)]
    async fn save_cnac(&self, cnac: &ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        let bytes = cnac.generate_proper_bytes()?;
        let cid = cnac.get_cid();
        let path = self.generate_cnac_local_save_path(cid, cnac.is_personal());
        let path_str = path.to_string_lossy();
        self.file_io.write_file(&path_str, &bytes).await?;
        self.memory_backend.save_cnac(cnac).await
    }

    async fn get_cnac_by_cid(
        &self,
        cid: u64,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        self.memory_backend.get_cnac_by_cid(cid).await
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        self.memory_backend.cid_is_registered(cid).await
    }

    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        let is_personal = self
            .memory_backend
            .clients
            .read()
            .get(&cid)
            .ok_or(AccountError::ClientNonExists(cid))?
            .is_personal();
        self.memory_backend.delete_cnac_by_cid(cid).await?;
        let path = self.generate_cnac_local_save_path(cid, is_personal);
        let path_str = path.to_string_lossy();
        self.file_io.remove_file(&path_str).await
    }

    async fn purge(&self) -> Result<usize, AccountError> {
        let paths = {
            let mut write = self.memory_backend.clients.write();
            write
                .drain()
                .map(|(cid, cnac)| self.generate_cnac_local_save_path(cid, cnac.is_personal()))
                .collect::<Vec<PathBuf>>()
        };

        let count = paths.len();

        // Drop in-memory global KV so the next byte_map call doesn't return ghost
        // state from before the purge. The on-disk copy is removed below via
        // `remove_dir_all`, but the in-memory cache must be cleared too.
        self.memory_backend.global_kv.write().clear();

        for path in paths {
            let path_str = path.to_string_lossy();
            self.file_io.remove_file(&path_str).await?;
        }

        let home_dir = self.directory_store.as_ref().unwrap().home.as_str();
        self.file_io.remove_dir_all(home_dir).await?;

        Ok(count)
    }

    async fn get_registered_impersonal_cids(
        &self,
        limit: Option<i32>,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        self.memory_backend
            .get_registered_impersonal_cids(limit)
            .await
    }

    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        self.memory_backend.get_username_by_cid(cid).await
    }

    async fn get_full_name_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        self.memory_backend.get_full_name_by_cid(cid).await
    }

    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        self.memory_backend
            .register_p2p_as_server(cid0, cid1)
            .await?;
        let (cnac0, cnac1) = {
            let read = self.memory_backend.clients.read();
            let cnac0 = read
                .get(&cid0)
                .cloned()
                .ok_or(AccountError::ClientNonExists(cid0))?;
            let cnac1 = read
                .get(&cid1)
                .cloned()
                .ok_or(AccountError::ClientNonExists(cid1))?;
            (cnac0, cnac1)
        };

        self.save_cnac(&cnac0).await?;
        self.save_cnac(&cnac1).await
    }

    async fn register_p2p_as_client(
        &self,
        session_cid: u64,
        peer_cid: u64,
        peer_username: String,
    ) -> Result<(), AccountError> {
        self.memory_backend
            .register_p2p_as_client(session_cid, peer_cid, peer_username)
            .await?;
        self.save_cnac_by_cid(session_cid).await
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        self.memory_backend
            .deregister_p2p_as_server(cid0, cid1)
            .await?;
        let (cnac0, cnac1) = {
            let read = self.memory_backend.clients.read();
            let cnac0 = read
                .get(&cid0)
                .cloned()
                .ok_or(AccountError::ClientNonExists(cid0))?;
            let cnac1 = read
                .get(&cid1)
                .cloned()
                .ok_or(AccountError::ClientNonExists(cid1))?;
            (cnac0, cnac1)
        };

        self.save_cnac(&cnac0).await?;
        self.save_cnac(&cnac1).await
    }

    async fn deregister_p2p_as_client(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        let res = self
            .memory_backend
            .deregister_p2p_as_client(session_cid, peer_cid)
            .await?;
        self.save_cnac_by_cid(session_cid).await.map(|_| res)
    }

    async fn get_hyperlan_peer_list(
        &self,
        session_cid: u64,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        self.memory_backend
            .get_hyperlan_peer_list(session_cid)
            .await
    }

    async fn get_client_metadata(
        &self,
        session_cid: u64,
    ) -> Result<Option<CNACMetadata>, AccountError> {
        self.memory_backend.get_client_metadata(session_cid).await
    }

    async fn get_clients_metadata(
        &self,
        limit: Option<i32>,
    ) -> Result<Vec<CNACMetadata>, AccountError> {
        self.memory_backend.get_clients_metadata(limit).await
    }

    async fn get_hyperlan_peer_by_cid(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        self.memory_backend
            .get_hyperlan_peer_by_cid(session_cid, peer_cid)
            .await
    }

    async fn hyperlan_peer_exists(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<bool, AccountError> {
        self.memory_backend
            .hyperlan_peer_exists(session_cid, peer_cid)
            .await
    }

    async fn hyperlan_peers_are_mutuals(
        &self,
        session_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<bool>, AccountError> {
        self.memory_backend
            .hyperlan_peers_are_mutuals(session_cid, peers)
            .await
    }

    async fn get_hyperlan_peers(
        &self,
        session_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<MutualPeer>, AccountError> {
        self.memory_backend
            .get_hyperlan_peers(session_cid, peers)
            .await
    }

    async fn get_hyperlan_peer_list_as_server(
        &self,
        session_cid: u64,
    ) -> Result<Option<Vec<MutualPeer>>, AccountError> {
        self.memory_backend
            .get_hyperlan_peer_list_as_server(session_cid)
            .await
    }

    async fn synchronize_hyperlan_peer_list_as_client(
        &self,
        cnac: &ClientNetworkAccount<R, Fcm>,
        peers: Vec<MutualPeer>,
    ) -> Result<(), AccountError> {
        self.memory_backend
            .synchronize_hyperlan_peer_list_as_client(cnac, peers)
            .await?;
        self.save_cnac(cnac).await
    }

    async fn get_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        self.memory_backend
            .get_byte_map_value(session_cid, peer_cid, key, sub_key)
            .await
    }

    async fn remove_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let (res, dest) = self
            .memory_backend
            .remove_byte_map_value_routed(session_cid, peer_cid, key, sub_key)
            .await?;
        self.flush_byte_map(session_cid, dest).await.map(|_| res)
    }

    async fn store_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let (res, dest) = self
            .memory_backend
            .store_byte_map_value_routed(session_cid, peer_cid, key, sub_key, value)
            .await?;
        self.flush_byte_map(session_cid, dest).await.map(|_| res)
    }

    async fn get_byte_map_values_by_key(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        self.memory_backend
            .get_byte_map_values_by_key(session_cid, peer_cid, key)
            .await
    }

    async fn remove_byte_map_values_by_key(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let (res, dest) = self
            .memory_backend
            .remove_byte_map_values_by_key_routed(session_cid, peer_cid, key)
            .await?;
        self.flush_byte_map(session_cid, dest).await.map(|_| res)
    }

    async fn stream_object_to_backend(
        &self,
        source: UnboundedReceiver<Vec<u8>>,
        sink_metadata: &VirtualObjectMetadata,
        status_tx: UnboundedSender<ObjectTransferStatus>,
    ) -> Result<(), AccountError> {
        let directory_store = self.directory_store.as_ref().unwrap();
        let is_virtual_file = matches!(
            sink_metadata.transfer_type,
            TransferType::RemoteEncryptedVirtualFilesystem { .. }
        );
        let metadata = sink_metadata.clone();
        let file_path = get_file_path(
            sink_metadata.cid,
            &sink_metadata.transfer_type,
            directory_store,
            Some(metadata.name.as_str()),
            self.file_io.as_ref(),
        )
        .await?;

        let file_path_str = file_path.to_string_lossy().to_string();
        log::debug!(target: "citadel", "Will stream object to {file_path_str}");

        let mut writer = self.file_io.create_streaming_writer(&file_path_str).await?;

        let _ = status_tx.send(ObjectTransferStatus::ReceptionBeginning(
            file_path.clone(),
            sink_metadata.clone(),
        ));

        if is_virtual_file {
            let metadata_path = get_revfs_file_metadata_path(&file_path);
            let metadata_path_str = metadata_path.to_string_lossy().to_string();
            let serialized = metadata.serialize_to_vector()?;
            self.file_io
                .write_file(&metadata_path_str, &serialized)
                .await?;
        }

        let mut stream = citadel_io::tokio_stream::wrappers::UnboundedReceiverStream::new(source);

        let mut total_bytes = 0usize;
        while let Some(chunk) = stream.next().await {
            log::debug!(target: "citadel", "Received {} byte chunk", chunk.len());
            total_bytes += chunk.len();
            if let Err(err) = writer.write_chunk(&chunk).await {
                let err_msg = format!("{err}");
                let _ = status_tx.send(ObjectTransferStatus::Fail(err_msg.clone()));
                return Err(AccountError::IoError(err_msg));
            }
        }

        writer.finish().await?;
        log::info!(target: "citadel", "Successfully wrote {total_bytes} bytes to {file_path_str}");

        Ok(())
    }

    async fn revfs_get_file_info(
        &self,
        cid: u64,
        virtual_path: std::path::PathBuf,
    ) -> Result<(Box<dyn ObjectSource>, VirtualObjectMetadata), AccountError> {
        let directory_store = self.directory_store.as_ref().unwrap();
        let file_path = get_file_path(
            cid,
            &TransferType::RemoteEncryptedVirtualFilesystem {
                virtual_path,
                security_level: Default::default(),
            },
            directory_store,
            None,
            self.file_io.as_ref(),
        )
        .await?;

        let metadata_path = get_revfs_file_metadata_path(&file_path);
        let metadata_path_str = metadata_path.to_string_lossy().to_string();
        let raw_metadata = self.file_io.read_file(&metadata_path_str).await?;
        let metadata: VirtualObjectMetadata =
            VirtualObjectMetadata::deserialize_from_owned_vector(raw_metadata)?;

        Ok((Box::new(file_path), metadata))
    }

    async fn revfs_delete(
        &self,
        cid: u64,
        virtual_path: std::path::PathBuf,
    ) -> Result<(), AccountError> {
        let directory_store = self.directory_store.as_ref().unwrap();
        let file_path = get_file_path(
            cid,
            &TransferType::RemoteEncryptedVirtualFilesystem {
                virtual_path,
                security_level: Default::default(),
            },
            directory_store,
            None,
            self.file_io.as_ref(),
        )
        .await?;
        let metadata_path = get_revfs_file_metadata_path(&file_path);

        delete_paths(&[metadata_path, file_path], self.file_io.as_ref()).await
    }
}

impl<R: Ratchet, Fcm: Ratchet> FileIOBackend<R, Fcm> {
    async fn save_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        let cnac = self
            .memory_backend
            .clients
            .read()
            .get(&cid)
            .cloned()
            .ok_or(AccountError::ClientNonExists(cid))?;
        self.save_cnac(&cnac).await
    }

    /// Persist the global KV store to disk. Used for server-global data
    /// not tied to any specific CNAC (e.g., workspace metadata stored via CID 0).
    ///
    /// Note: every mutating byte_map call that routes to `ByteMapDest::Global`
    /// rewrites the entire `global_kv.bin` (full bincode of the whole map).
    /// This is fine for the intended use — small server-global metadata under a
    /// bounded set of `session_cid`s — but is unsuitable for a workload that
    /// accumulates many entries or sees high write rates. If that ever changes,
    /// switch to per-`session_cid` files or an append-log instead of growing
    /// this single blob.
    async fn save_global_kv(&self) -> Result<(), AccountError> {
        let dirs = self
            .directory_store
            .as_ref()
            .ok_or_else(|| AccountError::Generic("Directory store not initialized".to_string()))?;
        let global_kv_path = format!("{}global_kv.bin", dirs.server_dir);
        let data = {
            let kv = self.memory_backend.global_kv.read();
            bincode::serialize(&*kv)
                .map_err(|e| AccountError::Generic(format!("Failed to serialize global KV: {e}")))?
        };
        self.file_io.write_file(&global_kv_path, &data).await?;
        Ok(())
    }

    /// Persist a byte_map mutation to whichever backing store the in-memory
    /// write actually targeted. Routing the flush by `ByteMapDest` (rather
    /// than by re-checking CNAC existence) prevents a TOCTOU where a CNAC
    /// is registered or deleted between the in-memory write and the flush —
    /// which would otherwise misroute the data and lose it on restart.
    async fn flush_byte_map(
        &self,
        session_cid: u64,
        dest: ByteMapDest,
    ) -> Result<(), AccountError> {
        match dest {
            ByteMapDest::Cnac => self.save_cnac_by_cid(session_cid).await,
            ByteMapDest::Global => self.save_global_kv().await,
        }
    }

    fn generate_cnac_local_save_path(&self, cid: u64, is_personal: bool) -> PathBuf {
        let dirs = self.directory_store.as_ref().unwrap();
        if is_personal {
            PathBuf::from(format!(
                "{}{}.{}",
                dirs.nac_dir_personal.as_str(),
                cid,
                CNAC_SERIALIZED_EXTENSION
            ))
        } else {
            PathBuf::from(format!(
                "{}{}.{}",
                dirs.nac_dir_impersonal.as_str(),
                cid,
                CNAC_SERIALIZED_EXTENSION
            ))
        }
    }
}

async fn get_file_path(
    source_cid: u64,
    transfer_type: &TransferType,
    directory_store: &DirectoryStore,
    target_name: Option<&str>,
    file_io: &dyn FileIO,
) -> Result<PathBuf, AccountError> {
    match transfer_type {
        TransferType::FileTransfer => {
            let name = target_name.ok_or_else(|| {
                AccountError::IoError(
                    "File transfer type specified, yet, no target name given".into(),
                )
            })?;
            let save_path = directory_store.file_transfer_dir.as_str();
            let base_path_str = format!("{save_path}{source_cid}");
            file_io.create_dir_all(&base_path_str).await?;

            let mut base_path = PathBuf::from(base_path_str);
            base_path.push(name);
            Ok(base_path)
        }
        TransferType::RemoteEncryptedVirtualFilesystem { virtual_path, .. } => {
            let virtual_dir = &crate::misc::prepare_virtual_path(virtual_path);
            crate::misc::validate_virtual_path(virtual_dir)?;
            let save_path = directory_store.virtual_dir.as_str();
            let file_path =
                PathBuf::from(format!("{save_path}{source_cid}{}", virtual_dir.display()));
            let mut file_path_dir = file_path.clone();
            let _ = file_path_dir.pop();

            let dir_str = file_path_dir.to_string_lossy();
            file_io.create_dir_all(&dir_str).await?;
            Ok(file_path)
        }
    }
}

fn get_revfs_file_metadata_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut metadata_path = format!("{}", path.as_ref().display());
    metadata_path.push_str(crate::misc::VIRTUAL_FILE_METADATA_EXT);
    crate::misc::prepare_virtual_path(metadata_path)
}

async fn delete_paths<T: AsRef<Path>>(
    paths: &[T],
    file_io: &dyn FileIO,
) -> Result<(), AccountError> {
    for path in paths {
        let path_str = path.as_ref().to_string_lossy();
        file_io.remove_file(&path_str).await?;
    }
    Ok(())
}
