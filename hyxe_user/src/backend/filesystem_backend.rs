use crate::backend::{BackendConnection, PersistenceHandler};
use async_trait::async_trait;
use hyxe_crypt::hyper_ratchet::Ratchet;
use crate::misc::{AccountError, CNACMetadata};
use crate::client_account::{ClientNetworkAccount, MutualPeer};
use hyxe_fs::system_file_manager::write_bytes_to;
use std::path::PathBuf;
use std::collections::HashMap;
use hyxe_fs::env::DirectoryStore;
use crate::prelude::NetworkAccount;
use crate::account_loader::{load_cnac_files, load_node_nac};
use crate::server_config_handler::sync_cnacs_and_nac_filesystem;
use std::collections::hash_map::RandomState;
use crate::hypernode_account::HyperNodeAccountInformation;
use std::sync::Arc;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// For handling I/O with the local filesystem
pub struct FilesystemBackend<R: Ratchet, Fcm: Ratchet> {
    clients_map: Option<Arc<RwLock<HashMap<u64, ClientNetworkAccount<R, Fcm>>>>>,
    directory_store: DirectoryStore,
    local_nac: Option<NetworkAccount<R, Fcm>>
}

#[async_trait]
impl<R: Ratchet, Fcm: Ratchet> BackendConnection<R, Fcm> for FilesystemBackend<R, Fcm> {
    async fn connect(&mut self, directory_store: &DirectoryStore) -> Result<(), AccountError> {
        let mut map = load_cnac_files(directory_store)?;
        let local_nac = load_node_nac(directory_store)?;
        sync_cnacs_and_nac_filesystem(&local_nac, &mut map)?;
        // NOTE: since we don't have access to the persistence handler yet, we will need to load it later
        self.local_nac = Some(local_nac);
        self.clients_map = Some(Arc::new(RwLock::new(map)));

        Ok(())
    }

    async fn post_connect(&self, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<(), AccountError> {
        // We must share the persistence handler to the local nac AND all cnacs
        self.local_nac().store_persistence_handler(persistence_handler);
        self.local_nac().save_to_local_fs()?;
        self.read_map().values().for_each(|cnac| cnac.store_persistence_handler(persistence_handler));

        // To not get accounts mixed up between tests
        if cfg!(feature = "localhost-testing") || std::env::var("LOCALHOST_TESTING").unwrap_or_default() == "1" {
            log::trace!(target: "lusna", "Purging home directory since localhost-testing is enabled");
            let _ = self.purge().await?;
        }

        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError> {
        Ok(true)
    }

    #[allow(unused_results)]
    async fn save_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        let bytes = cnac.generate_proper_bytes()?;
        let cid = cnac.get_cid();
        write_bytes_to(bytes, self.maybe_generate_cnac_local_save_path(cnac.get_cid(), cnac.is_personal()).ok_or(AccountError::Generic("Cannot generate a save path for the CNAC".into()))?)?;
        self.write_map().insert(cid, cnac);
        Ok(())
    }

    async fn get_cnac_by_cid(&self, cid: u64) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        Ok(self.read_map().get(&cid).cloned())
    }

    async fn get_client_by_username(&self, username: &str) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        Ok(self.read_map().iter().find(|(_, cnac)| cnac.get_username().eq(username))
            .map(|(_, cnac)| cnac.clone()))
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        Ok(self.local_nac().cid_exists_filesystem(cid))
    }

    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        let mut map = self.write_map();
        let cnac = map.remove(&cid).ok_or(AccountError::ClientNonExists(cid))?;
        self.delete_removed_cnac(cnac, map)
    }

    async fn save_all(&self) -> Result<(), AccountError> {
        let iter = {
            let write = self.write_map();
            write.values().cloned().collect::<Vec<ClientNetworkAccount<R, Fcm>>>()
        };

        for cnac in iter {
            cnac.save().await?;
        }

        self.local_nac().save_to_local_fs()
    }

    async fn purge(&self) -> Result<usize, AccountError> {
        let mut write = self.write_map();
        let count = write.len();

        for (cid, cnac) in write.drain() {
            log::trace!(target: "lusna", "Purging cid {}", cid);
            cnac.purge_from_fs_blocking()?;
        }

        let mut write = self.local_nac().write();
        write.cids_registered.clear();

        std::mem::drop(write);

        self.local_nac().save_to_local_fs()?;

        Ok(count)
    }

    fn maybe_generate_cnac_local_save_path(&self, cid: u64, is_personal: bool) -> Option<PathBuf> {
        Some(ClientNetworkAccount::<R, Fcm>::generate_local_save_path(cid, is_personal, &self.directory_store))
    }

    async fn client_only_generate_possible_cids(&self) -> Result<Vec<u64>, AccountError> {
        self.local_nac.as_ref().map(|r| r.client_only_generate_possible_cids()).ok_or_else(||AccountError::Generic("Local NAC not loaded".into()))
    }

    async fn find_first_valid_cid(&self, possible_cids: &Vec<u64>) -> Result<Option<u64>, AccountError> {
        Ok(self.local_nac().find_first_valid_cid_filesystem(possible_cids))
    }

    async fn username_exists(&self, username: &str) -> Result<bool, AccountError> {
        Ok(self.local_nac().username_exists_filesystem(username))
    }

    async fn register_cid_in_nac(&self, cid: u64, username: &str) -> Result<(), AccountError> {
        self.local_nac().register_cid_filesystem(cid, username)?;
        self.local_nac().save_to_local_fs()
    }

    async fn get_registered_impersonal_cids(&self, limit: Option<i32>) -> Result<Option<Vec<u64>>, AccountError> {
        let read = self.read_map();
        let iter = read.iter()
            .filter(|cnac| !cnac.1.is_personal())
            .map(|res| *res.0);

        let ret = if let Some(limit) = limit {
            iter.take(limit.abs() as usize).collect::<Vec<u64>>()
        } else {
            iter.collect::<Vec<u64>>()
        };

        if ret.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ret))
        }
    }

    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        Ok(self.read_map().get(&cid).map(|cnac| cnac.get_username()))
    }

    async fn get_cid_by_username(&self, username: &str) -> Result<Option<u64>, AccountError> {
        Ok(self.read_map().iter().find(|(_, cnac)| cnac.get_username().eq(username))
            .map(|(cid, _)| *cid))
    }

    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let (cnac0, cnac1) = {
            let read = self.read_map();
            let cnac0 = read.get(&cid0).cloned().ok_or(AccountError::ClientNonExists(cid0))?;
            let cnac1 = read.get(&cid1).cloned().ok_or(AccountError::ClientNonExists(cid1))?;
            (cnac0, cnac1)
        };

        cnac0.register_hyperlan_p2p_as_server_filesystem(&cnac1).await
    }

    async fn register_p2p_as_client(&self, implicated_cid: u64, peer_cid: u64, peer_username: String) -> Result<(), AccountError> {
        let cnac = self.get_cnac(implicated_cid)?;
        cnac.insert_hyperlan_peer(peer_cid, peer_username);
        cnac.save().await
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let read = self.read_map();
        let cnac0 = read.get(&cid0).ok_or(AccountError::ClientNonExists(cid0))?;
        let cnac1 = read.get(&cid1).ok_or(AccountError::ClientNonExists(cid1))?;

        cnac0.deregister_hyperlan_p2p_as_server_filesystem(cnac1)?;

        Ok(())
    }

    async fn deregister_p2p_as_client(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<MutualPeer>, AccountError> {
        Ok(self.get_cnac(implicated_cid)?.remove_hyperlan_peer(peer_cid))
    }

    async fn get_hyperlan_peer_list(&self, implicated_cid: u64) -> Result<Option<Vec<u64>>, AccountError> {
        let cnac = self.get_cnac(implicated_cid)?;
        Ok(cnac.get_hyperlan_peer_list())
    }

    async fn get_client_metadata(&self, implicated_cid: u64) -> Result<Option<CNACMetadata>, AccountError> {
        let cnac = self.get_cnac(implicated_cid)?;
        Ok(Some(cnac.get_metadata()))
    }

    async fn get_clients_metadata(&self, limit: Option<i32>) -> Result<Vec<CNACMetadata>, AccountError> {
        let read = self.read_map();
        if let Some(limit) = limit {
            Ok(read.values().into_iter().take(limit as _).map(|cnac| cnac.get_metadata()).collect())
        } else {
            Ok(read.values().into_iter().map(|cnac| cnac.get_metadata()).collect())
        }
    }

    async fn get_hyperlan_peer_by_cid(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<MutualPeer>, AccountError> {
        let cnac = self.get_cnac(implicated_cid)?;
        Ok(cnac.get_hyperlan_peer(peer_cid))
    }

    async fn hyperlan_peer_exists(&self, implicated_cid: u64, peer_cid: u64) -> Result<bool, AccountError> {
        Ok(self.get_cnac(implicated_cid)?.hyperlan_peer_exists(peer_cid))
    }

    async fn hyperlan_peers_are_mutuals(&self, implicated_cid: u64, peers: &Vec<u64>) -> Result<Vec<bool>, AccountError> {
        let cnac = self.get_cnac(implicated_cid)?;
        Ok(cnac.hyperlan_peers_exist(peers))
    }

    async fn get_hyperlan_peers(&self, implicated_cid: u64, peers: &Vec<u64>) -> Result<Vec<MutualPeer>, AccountError> {
        if peers.is_empty() {
            return Ok(Vec::new())
        }

        let cnac = self.get_cnac(implicated_cid)?;
        Ok(cnac.get_hyperlan_peers(peers).ok_or(AccountError::Generic("No peers exist locally".into()))?)
    }

    async fn get_hyperlan_peer_by_username(&self, implicated_cid: u64, username: &str) -> Result<Option<MutualPeer>, AccountError> {
        let cnac = self.get_cnac(implicated_cid)?;
        Ok(cnac.get_hyperlan_peer_by_username(username))
    }

    async fn get_hyperlan_peer_list_as_server(&self, implicated_cid: u64) -> Result<Option<Vec<MutualPeer>>, AccountError> {
        Ok(self.get_cnac(implicated_cid)?.get_hyperlan_peer_mutuals())
    }

    async fn synchronize_hyperlan_peer_list_as_client(&self, cnac: &ClientNetworkAccount<R, Fcm>, peers: Vec<MutualPeer>) -> Result<bool, AccountError> {
        Ok(cnac.synchronize_hyperlan_peer_list(peers))
    }

    async fn get_byte_map_value(&self, implicated_cid: u64, peer_cid: u64, key: &str, sub_key: &str) -> Result<Option<Vec<u8>>, AccountError> {
        let cnac = self.get_cnac(implicated_cid)?;
        let mut lock = cnac.write();
        Ok(lock.byte_map.entry(peer_cid).or_default().entry(key.to_string()).or_default().get(sub_key).cloned())
    }

    async fn remove_byte_map_value(&self, implicated_cid: u64, peer_cid: u64, key: &str, sub_key: &str) -> Result<Option<Vec<u8>>, AccountError> {
        let cnac = self.get_cnac(implicated_cid)?;
        let mut lock = cnac.write();
        Ok(lock.byte_map.entry(peer_cid).or_default().entry(key.to_string()).or_default().remove(sub_key))
    }

    async fn store_byte_map_value(&self, implicated_cid: u64, peer_cid: u64, key: &str, sub_key: &str, value: Vec<u8>) -> Result<Option<Vec<u8>>, AccountError> {
        let cnac = self.get_cnac(implicated_cid)?;
        let mut lock = cnac.write();
        Ok(lock.byte_map.entry(peer_cid).or_default().entry(key.to_string()).or_default().insert(sub_key.to_string(), value))
    }

    async fn get_byte_map_values_by_key(&self, implicated_cid: u64, peer_cid: u64, key: &str) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let cnac = self.get_cnac(implicated_cid)?;
        let mut lock = cnac.write();
        let map = lock.byte_map.entry(peer_cid).or_default().entry(key.to_string()).or_default().clone();
        Ok(map)
    }

    async fn remove_byte_map_values_by_key(&self, implicated_cid: u64, peer_cid: u64, key: &str) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let cnac = self.get_cnac(implicated_cid)?;
        let mut lock = cnac.write();
        let submap = lock.byte_map.entry(peer_cid).or_default().remove(key).unwrap_or_default();
        Ok(submap)
    }

    fn local_nac(&self) -> &NetworkAccount<R, Fcm> {
        self.local_nac.as_ref().unwrap()
    }
}

impl<R: Ratchet, Fcm: Ratchet> FilesystemBackend<R, Fcm> {
    fn read_map(&self) -> RwLockReadGuard<HashMap<u64, ClientNetworkAccount<R, Fcm>, RandomState>> {
        self.clients_map.as_ref().unwrap().read()
    }

    fn write_map(&self) -> RwLockWriteGuard<HashMap<u64, ClientNetworkAccount<R ,Fcm>, RandomState>> {
        self.clients_map.as_ref().unwrap().write()
    }

    fn get_cnac(&self, ref implicated_cid: u64) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        let read = self.read_map();
        read.get(implicated_cid).cloned().ok_or(AccountError::ClientNonExists(*implicated_cid))
    }

    // Called AFTER being removed from the hashmap
    #[allow(unused_results)]
    fn delete_removed_cnac(&self, removed_client: ClientNetworkAccount<R, Fcm>, write: RwLockWriteGuard<HashMap<u64, ClientNetworkAccount<R, Fcm>>>) -> Result<(), AccountError> {
        let cid = removed_client.get_cid();
        // Now, find any mutuals inside the removed client and clean them
        removed_client.view_hyperlan_peers(|peers| {
            for peer in peers {
                let peer_cid = peer.cid;
                if let Some(mutual) = write.get(&peer_cid) {
                    if mutual.remove_hyperlan_peer(cid).is_some() {
                        mutual.spawn_save_task_on_threadpool();
                    }
                }
            }
        });

        // Now that the account is removed from the list, it won't be saved upon synchronization.
        // The last step is to purge its existing content from the file system
        removed_client.purge_from_fs_blocking()?;
        if self.local_nac().remove_registered_cid_filesystem(removed_client.get_id()) {
            self.local_nac().save_to_local_fs()
        } else {
            Err(AccountError::Generic("Unable to remove registered CID from the filesystem".to_string()))
        }
    }
}

impl<R: Ratchet, Fcm: Ratchet> From<DirectoryStore> for FilesystemBackend<R, Fcm> {
    fn from(directory_store: DirectoryStore) -> Self {
        Self { directory_store, clients_map: None, local_nac: None }
    }
}