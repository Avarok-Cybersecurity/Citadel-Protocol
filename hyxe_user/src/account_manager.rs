use crate::network_account::NetworkAccount;
use crate::client_account::ClientNetworkAccount;
use std::sync::Arc;
use std::net::SocketAddr;
use crate::prelude::HyperNodeAccountInformation;
use crate::misc::AccountError;
use std::fmt::Display;
use hyxe_fs::hyxe_crypt::hyper_ratchet::HyperRatchet;
use crate::hypernode_account::NAC_SERIALIZED_EXTENSION;
use hyxe_fs::env::DirectoryStore;
use fcm::Client;
use crate::backend::{BackendType, PersistenceHandler};
use crate::backend::filesystem_backend::FilesystemBackend;
use crate::backend::BackendConnection;
use hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_crypt::fcm::fcm_ratchet::FcmRatchet;
use hyxe_crypt::prelude::SecBuffer;
use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_crypt::argon_container::{AsyncArgon, ArgonSettings, ArgonStatus, ServerArgonContainer, ArgonContainerType};
use crate::fcm::fcm_packet_processor::block_on_async;

/// The default manager for handling the list of users stored locally. It also allows for user creation, and is used especially
/// for when creating a new user via the registration service.
#[derive(Clone)]
pub struct AccountManager<R: Ratchet = HyperRatchet, Fcm: Ratchet = FcmRatchet> {
    fcm_client: Arc<Client>,
    persistence_handler: PersistenceHandler<R, Fcm>
}

impl<R: Ratchet, Fcm: Ratchet> AccountManager<R, Fcm> {

    /// `bind_addr`: Required for determining the local save directories for this instance
    /// `home_dir`: Optional. Overrides the default storage location for files
    #[allow(unused_results)]
    pub async fn new(bind_addr: SocketAddr, home_dir: Option<String>, backend_type: BackendType) -> Result<Self, AccountError> {
        // The below map should locally store: impersonal mode CNAC's, as well as personal remote server CNAC's
        let directory_store = hyxe_fs::env::setup_directories(bind_addr, NAC_SERIALIZED_EXTENSION, home_dir)?;
        let fcm_client = Arc::new(Client::new());

        let persistence_handler = match backend_type.clone() {
            BackendType::Filesystem => {
                // note: call connect HERE! we need &mut, and cant thru Arc
                let mut backend = FilesystemBackend::from(directory_store.clone());
                backend.connect(&directory_store).await?;
                PersistenceHandler::new(backend, directory_store)
            }

            #[cfg(feature = "enterprise")]
            BackendType::MySQLDatabase(url) => {
                use crate::backend::mysql_backend::SqlBackend;
                let mut backend = SqlBackend::from((url, backend_type));
                backend.connect(&directory_store).await?;
                PersistenceHandler::new(backend, directory_store)
            }
        };

        persistence_handler.post_connect(&persistence_handler)?;

        Ok(Self { persistence_handler, fcm_client })
    }

    /// Using an internal single-threaded executor, creates the account manager. NOTE: Since this wouldn't support connections to a database (timers require active polling for conn upkeep), this only supports a filesystem backend
    pub fn new_blocking(bind_addr: SocketAddr, home_dir: Option<String>) -> Result<Self, AccountError> {
        block_on_async(move || Self::new(bind_addr, home_dir, BackendType::Filesystem))?
    }

    /// Returns the directory store for this local node session
    pub fn get_directory_store(&self) -> &DirectoryStore {
        self.persistence_handler.directory_store()
    }

    /// Returns the fcm client
    pub fn fcm_client(&self) -> &Arc<Client> {
        &self.fcm_client
    }

    /// For testing purposes only
    pub fn debug_insert_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>) -> bool {
        self.persistence_handler.store_cnac(cnac);
        true
    }

    /// Once a valid and decrypted stage 4 packet gets received by the server (Bob), this function should be called
    /// to create the new CNAC. The generated CNAC will be assumed to be an impersonal hyperlan client
    ///
    /// This also generates the argon-2id password hash
    pub async fn register_impersonal_hyperlan_client_network_account<T: ToString, V: ToString>(&self, reserved_cid: u64, nac_other: NetworkAccount<R, Fcm>, username: T, password_hashed: SecBuffer, full_name: V, init_hyper_ratchet: R, fcm_keys: Option<FcmKeys>) -> Result<ClientNetworkAccount<R, Fcm>, AccountError<String>> {
        let settings = ArgonSettings::new_defaults(username.to_string().into_bytes());
        match AsyncArgon::hash(password_hashed, settings.clone()).await.map_err(|err| AccountError::Generic(err.to_string()))? {
            ArgonStatus::HashSuccess(hash_x2) => {
                let server_container = ArgonContainerType::Server(ServerArgonContainer::new(settings, hash_x2));
                let new_cnac = self.get_local_nac().create_client_account(reserved_cid, Some(nac_other), username, full_name, server_container, init_hyper_ratchet, fcm_keys).await?;
                // By using the local nac to create the CNAC, we ensured a unique CID and ensured that the config has been updated
                // What remains is to update the internal graph
                // To conclude the registration process, we need to:
                // [0] Add the new CNAC to the global map
                // [1] Insert the CNAC under the local impersonal server
                log::info!("Created impersonal CNAC ...");
                self.persistence_handler.store_cnac(new_cnac.clone());

                Ok(new_cnac)
            }

            _ => {
                Err(AccountError::Generic("Unable to hash password".to_string()))
            }
        }
    }

    /// whereas the HyperLAN server (Bob) runs `register_impersonal_hyperlan_client_network_account`, the registering
    /// HyperLAN Client (Alice) runs this function below
    pub async fn register_personal_hyperlan_server<'a, M: ToString + Display, V: ToString + Display>(&self, valid_cid: u64, hyper_ratchet: R, username: M, full_name: V, adjacent_nac: NetworkAccount<R, Fcm>, argon_container: ArgonContainerType, fcm_keys: Option<FcmKeys>) -> Result<ClientNetworkAccount<R, Fcm>, AccountError<String>> {
        let cnac = ClientNetworkAccount::<R, Fcm>::new_from_network_personal(valid_cid, hyper_ratchet, &username, &full_name, argon_container, adjacent_nac, self.persistence_handler.clone(), fcm_keys).await?;

        self.persistence_handler.register_cid(cnac.get_id(), &username.to_string()).await?;
        self.persistence_handler.store_cnac(cnac.clone());

        self.get_local_nac().save_to_local_fs()?;

        // At this point,
        Ok(cnac)
    }

    /// Determines if the HyperLAN client is registered
    /// Impersonal mode
    pub async fn hyperlan_cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        self.persistence_handler.cid_is_registered(cid).await
    }

    /// Returns a list of impersonal cids
    pub async fn get_registered_impersonal_cids(&self, limit: Option<i32>) -> Result<Option<Vec<u64>>, AccountError> {
        self.persistence_handler.get_registered_impersonal_cids(limit).await
    }

    /// Returns the CNAC with the supplied CID
    pub async fn get_client_by_cid(&self, cid: u64) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        self.persistence_handler.get_cnac_by_cid(cid, &self.persistence_handler).await
    }

    /// Gets username by CID
    pub async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        self.persistence_handler.get_username_by_cid(cid).await
    }

    /// Returns the first username detected. This is not advised to use, because overlapping usernames are entirely possible.
    /// Instead, use get_client_by_cid, as the cid is unique unlike the cid
    pub async fn get_client_by_username<T: AsRef<str>>(&self, username: T) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        self.persistence_handler.get_client_by_username(username.as_ref(), &self.persistence_handler).await
    }

    /// Allows a function to visit each value without cloning. This will be a no-op if probing a database, since that would be horribly performant
    pub fn visit_all_users_blocking(&self, fx: impl FnMut(&ClientNetworkAccount<R, Fcm>)) {
        if let Some(map) = self.persistence_handler.get_local_map() {
            map.read().unwrap().values().for_each(fx)
        }
    }

    /// Gets the CID by username
    pub async fn get_cid_by_username<T: AsRef<str>>(&self, username: T) -> Result<Option<u64>, AccountError> {
        self.persistence_handler.get_cid_by_username(username.as_ref()).await
    }

    /// Returns the number of accounts purged
    pub async fn purge(&self) -> Result<usize, AccountError> {
        self.persistence_handler.purge().await
    }

    /// Does not execute the registration process between two peers; it only consolidates the changes to the local CNAC
    /// returns true if success, false otherwise
    pub async fn register_hyperlan_p2p_at_endpoints<T: ToString>(&self, implicated_cid: u64, peer_cid: u64, adjacent_username: T) -> Result<(), AccountError> {
        let adjacent_username = adjacent_username.to_string();
        log::info!("Registering {} ({}) to {} (local)", &adjacent_username, peer_cid, implicated_cid);

        let cnac = self.persistence_handler.get_cnac_by_cid(implicated_cid, &self.persistence_handler).await?.ok_or(AccountError::ClientNonExists(implicated_cid))?;
        cnac.insert_hyperlan_peer(peer_cid, adjacent_username);
        cnac.save().await
    }

    /// Registers the two accounts together at the server
    pub async fn register_hyperlan_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        self.persistence_handler.register_p2p_as_server(cid0, cid1).await
    }

    /// Deregisters the two peers from each other
    pub async fn deregister_hyperlan_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        self.persistence_handler.deregister_p2p_as_server(cid0, cid1).await
    }

    /// Deletes a client by username
    pub async fn delete_client_by_username<T: AsRef<str>>(&self, username: T) -> Result<(), AccountError> {
        self.persistence_handler.delete_client_by_username(username.as_ref()).await
    }

    /// Deletes a client by cid. Returns true if a success
    #[allow(unused_results)]
    pub async fn delete_client_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        self.persistence_handler.delete_cnac_by_cid(cid).await
    }

    /// Gets a list of hyperlan peers for the given peer
    pub async fn get_hyperlan_peer_list(&self, implicated_cid: u64) -> Result<Option<Vec<u64>>, AccountError> {
        self.persistence_handler.get_hyperlan_peer_list(implicated_cid).await
    }

    /// Saves all the CNACs safely. This should be called during the shutdowns sequence.
    pub async fn save(&self) -> Result<(), AccountError<String>> {
        self.persistence_handler.save_all().await
    }

    /// returns the local nac
    pub fn get_local_nac(&self) -> &NetworkAccount<R, Fcm> {
        self.persistence_handler.local_nac()
    }

    /// Returns the persistence handler
    pub fn get_persistence_handler(&self) -> &PersistenceHandler<R, Fcm> {
        &self.persistence_handler
    }

    /// Returns the NID of the local system
    pub fn get_local_nid(&self) -> u64 {
        self.get_local_nac().get_id()
    }

    /// visits a CNAC without cloning. This should only be done at the endpoints!!
    pub fn visit_cnac_as_endpoint<J>(&self, cid: u64, fx: impl FnOnce(&ClientNetworkAccount<R, Fcm>) -> Option<J>) -> Option<J> {
        let map = self.persistence_handler.get_local_map()?;
        let map = map.read().ok()?;
        map.get(&cid).map(|c| fx(c))?
    }
}