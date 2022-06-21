use parking_lot::RwLock;
use crate::client_account::{ClientNetworkAccount, MutualPeer};
use std::collections::HashMap;
use hyxe_fs::hyxe_crypt::hyper_ratchet::Ratchet;
use crate::backend::BackendConnection;
use crate::misc::{AccountError, CNACMetadata};

#[derive(Default)]
pub(crate) struct MemoryBackend<R: Ratchet, Fcm: Ratchet> {
    pub(crate) clients: RwLock<HashMap<u64, ClientNetworkAccount<R, Fcm>>>
}

impl<R: Ratchet, Fcm: Ratchet> BackendConnection<R, Fcm> for MemoryBackend<R, Fcm> {
    async fn connect(&mut self) -> Result<(), AccountError> {
        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError> {
        Ok(true)
    }

    #[allow(unused_results)]
    async fn save_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        let cid = cnac.get_cid();
        self.clients.write().insert(cid, cnac);
        Ok(())
    }

    async fn get_cnac_by_cid(&self, cid: u64) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        Ok(self.clients.read().get(&cid).cloned())
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        Ok(self.clients.read().contains_key(&cid))
    }

    #[allow(unused_results)]
    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        self.clients.write().remove(&cid);
        Ok(())
    }

    async fn purge(&self) -> Result<usize, AccountError> {
        let write = self.clients.write();
        let len = write.len();
        self.clients.write().clear();
        Ok(len)
    }

    async fn get_registered_impersonal_cids(&self, limit: Option<i32>) -> Result<Option<Vec<u64>>, AccountError> {
        let mut iter = self.clients.read()
            .iter()
            .filter(|r| !r.1.is_personal())
            .map(|r| r.0);

        let ret: Vec<u64> = if let Some(limit) = limit {
            iter.take(limit as _).collect()
        } else {
            iter.collect()
        };

        if ret.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ret))
        }
    }

    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        Ok(self.clients.read().get(&cid).map(|r| r.get_username()).cloned())
    }

    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let read = self.clients.read();
        let cnac0 = read.get(&cid0).ok_or(AccountError::ClientNonExists(cid0))?;
        let cnac1 = read.get(&cid1).ok_or(AccountError::ClientNonExists(cid0))?;
        cnac0.register_hyperlan_p2p_as_server(&cnac1)
    }

    async fn register_p2p_as_client(&self, implicated_cid: u64, peer_cid: u64, peer_username: String) -> Result<(), AccountError> {
        self.clients.read().get(&implicated_cid).ok_or(AccountError::ClientNonExists(implicated_cid))?
            .insert_hyperlan_peer(peer_cid, peer_username);

        Ok(())
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let read = self.clients.read();
        let cnac0 = read.get(&cid0).ok_or(AccountError::ClientNonExists(cid0))?;
        let cnac1 = read.get(&cid1).ok_or(AccountError::ClientNonExists(cid0))?;

        cnac0.deregister_hyperlan_p2p_as_server(cnac1)
    }

    async fn deregister_p2p_as_client(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<MutualPeer>, AccountError> {
        Ok(self.clients.read().get(&implicated_cid).ok_or(AccountError::ClientNonExists(implicated_cid))?
            .remove_hyperlan_peer(peer_cid))
    }

    async fn get_hyperlan_peer_list(&self, implicated_cid: u64) -> Result<Option<Vec<u64>>, AccountError> {
        todo!()
    }

    async fn get_client_metadata(&self, implicated_cid: u64) -> Result<Option<CNACMetadata>, AccountError> {
        todo!()
    }

    async fn get_clients_metadata(&self, limit: Option<i32>) -> Result<Vec<CNACMetadata>, AccountError> {
        todo!()
    }

    async fn get_hyperlan_peer_by_cid(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<MutualPeer>, AccountError> {
        todo!()
    }

    async fn hyperlan_peer_exists(&self, implicated_cid: u64, peer_cid: u64) -> Result<bool, AccountError> {
        todo!()
    }

    async fn hyperlan_peers_are_mutuals(&self, implicated_cid: u64, peers: &Vec<u64>) -> Result<Vec<bool>, AccountError> {
        todo!()
    }

    async fn get_hyperlan_peers(&self, implicated_cid: u64, peers: &Vec<u64>) -> Result<Vec<MutualPeer>, AccountError> {
        todo!()
    }

    async fn get_hyperlan_peer_list_as_server(&self, implicated_cid: u64) -> Result<Option<Vec<MutualPeer>>, AccountError> {
        todo!()
    }

    async fn synchronize_hyperlan_peer_list_as_client(&self, cnac: &ClientNetworkAccount<R, Fcm>, peers: Vec<MutualPeer>) -> Result<(), AccountError> {
        todo!()
    }

    async fn get_byte_map_value(&self, implicated_cid: u64, peer_cid: u64, key: &str, sub_key: &str) -> Result<Option<Vec<u8>>, AccountError> {
        todo!()
    }

    async fn remove_byte_map_value(&self, implicated_cid: u64, peer_cid: u64, key: &str, sub_key: &str) -> Result<Option<Vec<u8>>, AccountError> {
        todo!()
    }

    async fn store_byte_map_value(&self, implicated_cid: u64, peer_cid: u64, key: &str, sub_key: &str, value: Vec<u8>) -> Result<Option<Vec<u8>>, AccountError> {
        todo!()
    }

    async fn get_byte_map_values_by_key(&self, implicated_cid: u64, peer_cid: u64, key: &str) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        todo!()
    }

    async fn remove_byte_map_values_by_key(&self, implicated_cid: u64, peer_cid: u64, key: &str) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        todo!()
    }
}