use crate::network_account::NetworkAccount;
use std::collections::HashMap;
use crate::client_account::ClientNetworkAccount;
use hyxe_fs::io::FsError;
use crate::account_loader::{load_node_nac, load_cnac_files};
use std::sync::Arc;
use hyxe_fs::hyxe_crypt::drill::Drill;
use std::net::SocketAddr;
use crate::prelude::HyperNodeAccountInformation;
use crate::misc::AccountError;
use hyxe_fs::hyxe_crypt::prelude::PostQuantumContainer;
use secstr::SecVec;
use std::fmt::Display;
use crossbeam_utils::sync::{ShardedLock, ShardedLockReadGuard, ShardedLockWriteGuard};
use std::collections::hash_map::RandomState;

/// The default manager for handling the list of users stored locally. It also allows for user creation, and is used especially
/// for when creating a new user via the registration service.
pub struct AccountManager {
    /// A set of all local CNACs loaded at runtime + created during network registrations
    map: Arc<ShardedLock<HashMap<u64, ClientNetworkAccount>>>,
    local_nac: NetworkAccount,
}

unsafe impl Send for AccountManager {}
unsafe impl Sync for AccountManager {}

impl AccountManager {
    /// REQUIREMENT: Local NAC must exist. Therefore, for the local node's initialization phase, this must be created
    /// This returns an empty inner domain because it does not load information from a pre-existing [NetworkMap]: It doesn't exist yet!
    ///
    /// `bind_addr`: Required for determining the local save directories for this instance
    /// `home_dir`: Optional. Overrides the default storage location for files
    #[allow(unused_results)]
    pub async fn new(bind_addr: SocketAddr, home_dir: Option<String>) -> Result<Self, FsError<String>> {
        // The below map should locally store: impersonal mode CNAC's, as well as personal remote server CNAC's
        if !hyxe_fs::env::setup_directories(bind_addr, home_dir) {
            return Err(FsError::IoError("Unable to setup directories".to_string()));
        }

        let (highest_cid, mut map) = load_cnac_files().await?;
        let local_nac = load_node_nac(&mut map).map_err(|err| FsError::IoError(err.to_string()))?;
        local_nac.set_highest_cid(highest_cid);

        let map = Arc::new(ShardedLock::new(map));
        Ok(Self { map, local_nac })
    }

    fn read_map(&self) -> ShardedLockReadGuard<HashMap<u64, ClientNetworkAccount, RandomState>> {
        self.map.read().unwrap()
    }

    fn write_map(&self) -> ShardedLockWriteGuard<HashMap<u64, ClientNetworkAccount, RandomState>> {
        self.map.write().unwrap()
    }

    /// Once a valid and decrypted stage 4 packet gets received by the server (Bob), this function should be called
    /// to create the new CNAC. The generated CNAC will be assumed to be an impersonal hyperlan client
    pub fn register_impersonal_hyperlan_client_network_account<T: ToString, V: ToString>(&self, reserved_cid: u64, nac_other: NetworkAccount, username: T, password: SecVec<u8>, full_name: V, post_quantum_container: &PostQuantumContainer) -> Result<ClientNetworkAccount, AccountError<String>> {
        let new_cnac = self.local_nac.create_client_account::<_,_,&[u8]>(reserved_cid, Some(nac_other), username, password, full_name, post_quantum_container, None)?;
        // By using the local nac to create the CNAC, we ensured a unique CID and ensured that the config has been updated
        // What remains is to update the internal graph
        // To conclude the registration process, we need to:
        // [0] Add the new CNAC to the global map
        // [1] Insert the CNAC under the local impersonal server
        log::info!("Created impersonal CNAC ...");
        assert!(self.write_map().insert(new_cnac.get_id(), new_cnac.clone()).is_none());
        Ok(new_cnac)
    }

    /// whereas the HyperLAN server (Bob) runs `register_impersonal_hyperlan_client_network_account`, the registering
    /// HyperLAN Client (Alice) runs this function below
    pub fn register_personal_hyperlan_server<T: AsRef<[u8]>, R: ToString + Display, V: ToString + Display>(&self, toolset_bytes: T, username: R, full_name: V, adjacent_nac: NetworkAccount, post_quantum_container: &PostQuantumContainer, password: SecVec<u8>) -> Result<ClientNetworkAccount, AccountError<String>> {
        let cnac = ClientNetworkAccount::new_from_network_personal(toolset_bytes, &username, password, &full_name, adjacent_nac, post_quantum_container)?;
        self.local_nac.register_cid(cnac.get_id(), &username);

        let mut map = self.write_map();
        if let Some(_prev) = map.insert(cnac.get_id(), cnac.clone()) {
            panic!("CID collision occurred. This must be fixed before release");
        } else {
            log::info!("Successfully added CID to AccountManager Hashmap");
        }

        Ok(cnac)
    }

    /// Determines if the HyperLAN client is registered
    /// Impersonal mode
    pub fn hyperlan_cid_is_registered(&self, cid: u64) -> bool {
        let local_nac = self.local_nac.read();
        local_nac.cids_registered.contains_key(&cid)
    }

    /// Returns a list of registered HyperLAN cids
    pub fn get_registered_hyperlan_cids(&self) -> Option<Vec<u64>> {
        let local_nac = self.local_nac.read();
        if !local_nac.cids_registered.is_empty() {
            Some(local_nac.cids_registered.keys().cloned().collect::<Vec<u64>>())
        } else {
            None
        }
    }

    /// Returns the CNAC with the supplied CID
    pub fn get_client_by_cid(&self, cid: u64) -> Option<ClientNetworkAccount> {
        self.read_map().get(&cid).cloned()
    }

    /// Blocking version of get_username_by_cid
    pub fn get_username_by_cid(&self, cid: u64) -> Option<String> {
        self.visit_cnac(cid, |cnac| Some(cnac.get_username()))
    }

    /// Gets a drill for a specific CID.
    /// `drill_version`: If this is None, the latest drill version is obtained. Else, the specified drill version is obtained
    pub fn get_drill(&self, cid: u64, drill_version: Option<u32>) -> Option<Drill> {
        self.visit_cnac(cid, |cnac| cnac.get_drill(drill_version))
    }

    /// Returns the first username detected. This is not advised to use, because overlapping usernames are entirely possible.
    /// Instead, use get_client_by_cid, as the cid is unique unlike the cid
    pub fn get_client_by_username<T: AsRef<str>>(&self, username: T) -> Option<ClientNetworkAccount> {
        let username = username.as_ref();
        self.read_map().iter().find(|(_, cnac)| cnac.read().username.eq(username))
            .map(|(_, cnac)| cnac.clone())
    }

    /// Allows a function to visit each value without cloning
    pub fn visit_all_users_blocking(&self, mut fx: impl FnMut(&ClientNetworkAccount)) {
        self.read_map().values().for_each(|cnac| fx(cnac))
    }

    /// Gets the CID by username
    pub fn get_cid_by_username<T: AsRef<str>>(&self, username: T) -> Option<u64> {
        let username = username.as_ref();
        self.read_map().iter().find(|(_, cnac)| cnac.read().username.eq(username))
            .map(|(cid, _)| *cid)
    }

    /// Returns a client by IP Address
    pub fn get_client_by_addr(&self, addr: &SocketAddr, prefer_ipv6: bool) -> Option<ClientNetworkAccount> {
        let read = self.read_map();
        for (_, cnac) in read.iter() {
            if let Some(ip) = cnac.read().adjacent_nac.as_ref().unwrap().get_addr(prefer_ipv6) {
                if ip.eq(addr) {
                    return Some(cnac.clone())
                }
            }
        }

        None
    }

    /// Returns the number of accounts purged
    pub fn purge(&self) -> usize {
        let mut write = self.write_map();
        let count = write.len();
        for (cid, mut cnac) in write.drain() {
            log::info!("Purging cid {}", cid);
            cnac.purge_from_fs_blocking().unwrap()
        }

        let mut write = self.local_nac.write();
        write.cids_registered.clear();

        count
    }

    /// Does not execute the registration process between two peers; it only consolidates the changes to the local CNAC
    /// returns true if success, false otherwise
    pub fn register_hyperlan_client_to_client_locally<T: ToString>(&self, implicated_cid: u64, peer_cid: u64, adjacent_username: T) -> bool {
        let adjacent_username = adjacent_username.to_string();
        log::info!("Registering {} ({}) to {} (local)", &adjacent_username, peer_cid, implicated_cid);

        let read = self.read_map();
        if let Some(cnac) = read.get(&implicated_cid) {
            cnac.insert_hyperlan_peer(peer_cid, adjacent_username);
            cnac.blocking_save_to_local_fs().is_ok()
        } else {
            false
        }
    }

    /// Deletes a client by username
    pub fn delete_client_by_username<T: AsRef<str>>(&self, username: T) -> bool {
        if let Some(cid) = self.get_cid_by_username(username) {
            self.delete_client_by_cid(cid)
        } else {
            false
        }
    }

    /// Deletes a client by cid. Returns true if a success
    pub fn delete_client_by_cid(&self, cid: u64) -> bool {
        let mut write = self.write_map();
        if let Some(mut removed_client) = write.remove(&cid) {
            // Now that the account is removed from the list, it won't be saved upon synchronization.
            // The last step is to purge its existing content from the file system
            if removed_client.purge_from_fs_blocking().is_ok() {
                // Finally, remove the entry in the config file
                self.local_nac.remove_registered_cid(removed_client.get_id())
            } else {
                log::error!("Unable to remove client {} from the internal filesystem. Please report to administrator", cid);
                false
            }
        } else {
            false
        }
    }

    /// Saves all the CNACs to the local filesystem safely. This should be called during the shutdowns sequence.
    /// This also saves the network map to the local filesystem
    pub async fn async_save_to_local_fs(&self) -> Result<(), AccountError<String>> {
        let write = self.write_map();
        let iter = write.iter();
        for (_, cnac) in iter {
            cnac.clone().async_save_to_local_fs().await?
        }
        Ok(())
    }

    /// returns the local nac
    pub fn get_local_nac(&self) -> &NetworkAccount {
        &self.local_nac
    }

    /// Returns the NID of the local system
    pub fn get_local_nid(&self) -> u64 {
        self.local_nac.get_id()
    }

    /// visits a CNAC without cloning
    pub fn visit_cnac<J>(&self, cid: u64, fx: impl FnOnce(&ClientNetworkAccount) -> Option<J>) -> Option<J> {
        let read = self.read_map();
        fx(read.get(&cid)?)
    }
}

impl Clone for AccountManager {
    fn clone(&self) -> Self {
        Self { map: self.map.clone(), local_nac: self.local_nac.clone() }
    }
}