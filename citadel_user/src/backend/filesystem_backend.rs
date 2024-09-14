use crate::account_loader::load_cnac_files;
use crate::backend::memory::MemoryBackend;
use crate::backend::BackendConnection;
use crate::client_account::ClientNetworkAccount;
use crate::directory_store::DirectoryStore;
use crate::misc::{AccountError, CNACMetadata};
use crate::prelude::CNAC_SERIALIZED_EXTENSION;
use crate::serialization::SyncIO;
use async_trait::async_trait;
use citadel_crypt::stacked_ratchet::Ratchet;
use citadel_crypt::streaming_crypt_scrambler::ObjectSource;
use citadel_io::tokio;
use citadel_io::tokio_stream::StreamExt;
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::{ObjectTransferStatus, TransferType, VirtualObjectMetadata};
use citadel_types::user::MutualPeer;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// For handling I/O with the local filesystem
pub struct FilesystemBackend<R: Ratchet, Fcm: Ratchet> {
    memory_backend: MemoryBackend<R, Fcm>,
    directory_store: Option<DirectoryStore>,
    home_dir: String,
}

#[async_trait]
impl<R: Ratchet, Fcm: Ratchet> BackendConnection<R, Fcm> for FilesystemBackend<R, Fcm> {
    async fn connect(&mut self) -> Result<(), AccountError> {
        let directory_store = crate::directory_store::setup_directories(self.home_dir.clone())?;
        let map = load_cnac_files(&directory_store)?;
        // ensure the in-memory database has the clients loaded
        *self.memory_backend.clients.get_mut() = map;
        self.directory_store = Some(directory_store);

        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError> {
        Ok(true)
    }

    #[allow(unused_results)]
    async fn save_cnac(&self, cnac: &ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        // save to filesystem, then, synchronize to memory
        let bytes = cnac.generate_proper_bytes()?;
        let cid = cnac.get_cid();
        let path = self.generate_cnac_local_save_path(cid, cnac.is_personal());
        // TODO: The below line of code fails
        std::fs::write(path, bytes).map_err(|err| AccountError::Generic(err.to_string()))?;
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
        std::fs::remove_file(path).map_err(|err| AccountError::Generic(err.to_string()))
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

        for path in paths {
            tokio::fs::remove_file(path)
                .await
                .map_err(|err| AccountError::Generic(err.to_string()))?;
        }

        // delete the home directory
        let home_dir = self.directory_store.as_ref().unwrap().home.as_str();
        tokio::fs::remove_dir_all(home_dir)
            .await
            .map_err(|err| AccountError::Generic(err.to_string()))?;

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
        implicated_cid: u64,
        peer_cid: u64,
        peer_username: String,
    ) -> Result<(), AccountError> {
        self.memory_backend
            .register_p2p_as_client(implicated_cid, peer_cid, peer_username)
            .await?;
        self.save_cnac_by_cid(implicated_cid).await
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
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        let res = self
            .memory_backend
            .deregister_p2p_as_client(implicated_cid, peer_cid)
            .await?;
        self.save_cnac_by_cid(implicated_cid).await.map(|_| res)
    }

    async fn get_hyperlan_peer_list(
        &self,
        implicated_cid: u64,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        self.memory_backend
            .get_hyperlan_peer_list(implicated_cid)
            .await
    }

    async fn get_client_metadata(
        &self,
        implicated_cid: u64,
    ) -> Result<Option<CNACMetadata>, AccountError> {
        self.memory_backend
            .get_client_metadata(implicated_cid)
            .await
    }

    async fn get_clients_metadata(
        &self,
        limit: Option<i32>,
    ) -> Result<Vec<CNACMetadata>, AccountError> {
        self.memory_backend.get_clients_metadata(limit).await
    }

    async fn get_hyperlan_peer_by_cid(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        self.memory_backend
            .get_hyperlan_peer_by_cid(implicated_cid, peer_cid)
            .await
    }

    async fn hyperlan_peer_exists(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<bool, AccountError> {
        self.memory_backend
            .hyperlan_peer_exists(implicated_cid, peer_cid)
            .await
    }

    async fn hyperlan_peers_are_mutuals(
        &self,
        implicated_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<bool>, AccountError> {
        self.memory_backend
            .hyperlan_peers_are_mutuals(implicated_cid, peers)
            .await
    }

    async fn get_hyperlan_peers(
        &self,
        implicated_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<MutualPeer>, AccountError> {
        self.memory_backend
            .get_hyperlan_peers(implicated_cid, peers)
            .await
    }

    async fn get_hyperlan_peer_list_as_server(
        &self,
        implicated_cid: u64,
    ) -> Result<Option<Vec<MutualPeer>>, AccountError> {
        self.memory_backend
            .get_hyperlan_peer_list_as_server(implicated_cid)
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
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        self.memory_backend
            .get_byte_map_value(implicated_cid, peer_cid, key, sub_key)
            .await
    }

    async fn remove_byte_map_value(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let res = self
            .memory_backend
            .remove_byte_map_value(implicated_cid, peer_cid, key, sub_key)
            .await?;
        self.save_cnac_by_cid(implicated_cid).await.map(|_| res)
    }

    async fn store_byte_map_value(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let res = self
            .memory_backend
            .store_byte_map_value(implicated_cid, peer_cid, key, sub_key, value)
            .await?;
        self.save_cnac_by_cid(implicated_cid).await.map(|_| res)
    }

    async fn get_byte_map_values_by_key(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let res = self
            .memory_backend
            .get_byte_map_values_by_key(implicated_cid, peer_cid, key)
            .await?;
        self.save_cnac_by_cid(implicated_cid).await.map(|_| res)
    }

    async fn remove_byte_map_values_by_key(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let res = self
            .memory_backend
            .remove_byte_map_values_by_key(implicated_cid, peer_cid, key)
            .await?;
        self.save_cnac_by_cid(implicated_cid).await.map(|_| res)
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
        )
        .await?;

        log::info!(target: "citadel", "Will stream object to {file_path:?}");
        let file = tokio::fs::File::create(&file_path)
            .await
            .map_err(|err| AccountError::IoError(err.to_string()))?;

        let _ = status_tx.send(ObjectTransferStatus::ReceptionBeginning(
            file_path.clone(),
            sink_metadata.clone(),
        ));

        let mut size = 0;
        let mut writer = tokio::io::BufWriter::new(file);
        let mut reader = citadel_io::tokio_util::io::StreamReader::new(
            citadel_io::tokio_stream::wrappers::UnboundedReceiverStream::new(source).map(|r| {
                size += r.len();
                Ok(std::io::Cursor::new(r)) as Result<std::io::Cursor<Vec<u8>>, std::io::Error>
            }),
        );

        if is_virtual_file {
            // start by writing the metadata file next to it
            let metadata_path = get_revfs_file_metadata_path(&file_path);
            let serialized = metadata.serialize_to_vector()?;
            tokio::fs::write(metadata_path, serialized)
                .await
                .map_err(|err| AccountError::IoError(err.to_string()))?
        }

        match tokio::io::copy(&mut reader, &mut writer).await {
            Ok(bytes_written) => {
                log::info!(target: "citadel", "Successfully wrote {bytes_written} bytes to {file_path:?}");
            }

            Err(err) => {
                log::error!(target: "citadel", "Error while copying from reader to writer: {err}");
                status_tx
                    .send(ObjectTransferStatus::Fail(err.to_string()))
                    .map_err(|err| AccountError::IoError(err.to_string()))?;
                return Err(AccountError::IoError(err.to_string()));
            }
        }

        writer
            .flush()
            .await
            .map_err(|err| AccountError::IoError(err.to_string()))?;

        writer
            .into_inner()
            .sync_all()
            .await
            .map_err(|err| AccountError::IoError(err.to_string()))?;

        /*
        let plaintext_length = metadata.plaintext_length;
        loop {
            // Loop until the file's size is equal to the plaintext length
            let file = tokio::fs::File::open(&file_path).await
                .map_err(|err| AccountError::IoError(err.to_string()))?;
            let metadata = file.metadata().await
                .map_err(|err| AccountError::IoError(err.to_string()))?;
            if metadata.len() >= plaintext_length as u64 {
                return Ok(())
            }
            log::error!(target: "citadel", "File len: {} | Plaintext len: {}", metadata.len(), plaintext_length);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }*/
        Ok(())
    }

    async fn revfs_get_file_info(
        &self,
        cid: u64,
        virtual_path: std::path::PathBuf,
    ) -> Result<(Box<dyn ObjectSource>, SecurityLevel), AccountError> {
        let directory_store = self.directory_store.as_ref().unwrap();
        let file_path = get_file_path(
            cid,
            &TransferType::RemoteEncryptedVirtualFilesystem {
                virtual_path,
                security_level: Default::default(),
            },
            directory_store,
            None,
        )
        .await?;

        let metadata_path = get_revfs_file_metadata_path(&file_path);
        // first, figure out what security level it was encrypted at. This data should be passed back to the client pulling
        // this file
        let raw_metadata = tokio::fs::read(&metadata_path)
            .await
            .map_err(|err| AccountError::IoError(err.to_string()))?;
        let metadata: VirtualObjectMetadata =
            VirtualObjectMetadata::deserialize_from_owned_vector(raw_metadata)?;

        let security_level = metadata.get_security_level().ok_or_else(|| AccountError::IoError("The requested file was not designated as a RE-VFS type, yet, a metadata file existed for it".into()))?;

        Ok((Box::new(file_path), security_level))
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
        )
        .await?;
        let metadata_path = get_revfs_file_metadata_path(&file_path);

        delete_paths(&[metadata_path, file_path]).await
    }
}

impl<R: Ratchet, Fcm: Ratchet> FilesystemBackend<R, Fcm> {
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

impl<R: Ratchet, Fcm: Ratchet> From<String> for FilesystemBackend<R, Fcm> {
    fn from(home_dir: String) -> Self {
        Self {
            home_dir,
            memory_backend: MemoryBackend::default(),
            directory_store: None,
        }
    }
}

// works for RE-FVS and standard file transfers
async fn get_file_path(
    source_cid: u64,
    transfer_type: &TransferType,
    directory_store: &DirectoryStore,
    target_name: Option<&str>,
) -> Result<PathBuf, AccountError> {
    match transfer_type {
        TransferType::FileTransfer => {
            // TODO: ensure for sources that come from bytes, the name is randomly generated
            // to prevent collisions
            let name = target_name.ok_or_else(|| {
                AccountError::IoError(
                    "File transfer type specified, yet, no target name given".into(),
                )
            })?;
            let save_path = directory_store.file_transfer_dir.as_str();
            let mut base_path = PathBuf::from(format!("{save_path}{source_cid}"));

            // create the directory in case it doesn't exist
            tokio::fs::create_dir_all(&base_path)
                .await
                .map_err(|err| AccountError::IoError(err.to_string()))?;

            // finally, add the file name
            base_path.push(name);

            Ok(base_path)
        }
        TransferType::RemoteEncryptedVirtualFilesystem { virtual_path, .. } => {
            let virtual_dir = &crate::misc::prepare_virtual_path(virtual_path);
            crate::misc::validate_virtual_path(virtual_dir)?;
            let save_path = directory_store.virtual_dir.as_str();
            let file_path =
                PathBuf::from(format!("{save_path}{source_cid}{}", virtual_dir.display()));
            // create the directory for the file if it doesn't exist
            let mut file_path_dir = file_path.clone();
            let _ = file_path_dir.pop();

            // create the directory in case it doesn't exist
            tokio::fs::create_dir_all(&file_path_dir)
                .await
                .map_err(|err| AccountError::IoError(err.to_string()))?;
            Ok(file_path)
        }
    }
}

fn get_revfs_file_metadata_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut metadata_path = format!("{}", path.as_ref().display());
    metadata_path.push_str(crate::misc::VIRTUAL_FILE_METADATA_EXT);
    crate::misc::prepare_virtual_path(metadata_path)
}

async fn delete_paths<T: AsRef<Path>, R: AsRef<[T]>>(paths: R) -> Result<(), AccountError> {
    let paths = paths.as_ref();
    for path in paths {
        tokio::fs::remove_file(path)
            .await
            .map_err(|err| AccountError::IoError(err.to_string()))?;
    }

    Ok(())
}
