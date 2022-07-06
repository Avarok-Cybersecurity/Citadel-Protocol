use super::utils::StreamableTargetInformation;
use crate::backend::utils::ObjectTransferStatus;
use crate::backend::BackendConnection;
use crate::client_account::{ClientNetworkAccount, MutualPeer};
use crate::misc::{AccountError, CNACMetadata};
use async_trait::async_trait;
use hyxe_crypt::stacked_ratchet::Ratchet;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub(crate) struct MemoryBackend<R: Ratchet, Fcm: Ratchet> {
    pub(crate) clients: RwLock<HashMap<u64, ClientNetworkAccount<R, Fcm>>>,
}

impl<R: Ratchet, Fcm: Ratchet> Default for MemoryBackend<R, Fcm> {
    fn default() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl<R: Ratchet, Fcm: Ratchet> BackendConnection<R, Fcm> for MemoryBackend<R, Fcm> {
    async fn connect(&mut self) -> Result<(), AccountError> {
        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError> {
        Ok(true)
    }

    #[allow(unused_results)]
    async fn save_cnac(&self, cnac: &ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        let cid = cnac.get_cid();
        self.clients.write().insert(cid, cnac.clone());
        Ok(())
    }

    async fn get_cnac_by_cid(
        &self,
        cid: u64,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        Ok(self.clients.read().get(&cid).cloned())
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        Ok(self.clients.read().contains_key(&cid))
    }

    #[allow(unused_results)]
    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        let mut write = self.clients.write();
        let cl = write
            .remove(&cid)
            .ok_or_else(|| AccountError::ClientNonExists(cid))?;

        // delete all related peer entries in other CNACs
        if let Some(peers) = cl.get_hyperlan_peer_list() {
            for peer in peers {
                if let Some(peer) = write.get(&peer) {
                    peer.remove_hyperlan_peer(cid);
                }
            }
        }

        Ok(())
    }

    async fn purge(&self) -> Result<usize, AccountError> {
        let mut write = self.clients.write();
        let len = write.len();
        write.clear();
        Ok(len)
    }

    async fn get_registered_impersonal_cids(
        &self,
        limit: Option<i32>,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        let read = self.clients.read();
        let iter = read.iter().filter(|r| !r.1.is_personal()).map(|r| r.0);

        let ret: Vec<u64> = if let Some(limit) = limit {
            iter.take(limit as _).copied().collect()
        } else {
            iter.copied().collect()
        };

        if ret.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ret))
        }
    }

    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        Ok(self.clients.read().get(&cid).map(|r| r.get_username()))
    }

    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let read = self.clients.read();
        let cnac0 = read.get(&cid0).ok_or(AccountError::ClientNonExists(cid0))?;
        let cnac1 = read.get(&cid1).ok_or(AccountError::ClientNonExists(cid0))?;
        cnac0.register_hyperlan_p2p_as_server(&cnac1)
    }

    async fn register_p2p_as_client(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        peer_username: String,
    ) -> Result<(), AccountError> {
        self.clients
            .read()
            .get(&implicated_cid)
            .ok_or(AccountError::ClientNonExists(implicated_cid))?
            .insert_hyperlan_peer(peer_cid, peer_username);

        Ok(())
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let read = self.clients.read();
        let cnac0 = read.get(&cid0).ok_or(AccountError::ClientNonExists(cid0))?;
        let cnac1 = read.get(&cid1).ok_or(AccountError::ClientNonExists(cid0))?;

        cnac0.deregister_hyperlan_p2p_as_server(cnac1)
    }

    async fn deregister_p2p_as_client(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        Ok(self
            .clients
            .read()
            .get(&implicated_cid)
            .ok_or(AccountError::ClientNonExists(implicated_cid))?
            .remove_hyperlan_peer(peer_cid))
    }

    async fn get_hyperlan_peer_list(
        &self,
        implicated_cid: u64,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        let read = self.clients.read();
        if let Some(cnac) = read.get(&implicated_cid) {
            Ok(cnac.get_hyperlan_peer_list())
        } else {
            Ok(None)
        }
    }

    async fn get_client_metadata(
        &self,
        implicated_cid: u64,
    ) -> Result<Option<CNACMetadata>, AccountError> {
        let read = self.clients.read();
        if let Some(cnac) = read.get(&implicated_cid) {
            Ok(Some(cnac.get_metadata()))
        } else {
            Ok(None)
        }
    }

    async fn get_clients_metadata(
        &self,
        limit: Option<i32>,
    ) -> Result<Vec<CNACMetadata>, AccountError> {
        let read = self.clients.read();
        if let Some(limit) = limit {
            Ok(read
                .values()
                .take(limit as _)
                .map(|r| r.get_metadata())
                .collect())
        } else {
            Ok(read.values().map(|r| r.get_metadata()).collect())
        }
    }

    async fn get_hyperlan_peer_by_cid(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        let read = self.clients.read();
        if let Some(cnac) = read.get(&implicated_cid) {
            Ok(cnac.get_hyperlan_peer(peer_cid))
        } else {
            Ok(None)
        }
    }

    async fn hyperlan_peer_exists(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<bool, AccountError> {
        self.get_hyperlan_peer_by_cid(implicated_cid, peer_cid)
            .await
            .map(|r| r.is_some())
    }

    async fn hyperlan_peers_are_mutuals(
        &self,
        implicated_cid: u64,
        peers: &Vec<u64>,
    ) -> Result<Vec<bool>, AccountError> {
        if peers.is_empty() {
            return Ok(Default::default());
        }

        let read = self.clients.read();
        if let Some(cnac) = read.get(&implicated_cid) {
            Ok(cnac.hyperlan_peers_exist(peers))
        } else {
            Ok(Default::default())
        }
    }

    async fn get_hyperlan_peers(
        &self,
        implicated_cid: u64,
        peers: &Vec<u64>,
    ) -> Result<Vec<MutualPeer>, AccountError> {
        if peers.is_empty() {
            return Ok(Default::default());
        }

        let read = self.clients.read();
        if let Some(cnac) = read.get(&implicated_cid) {
            Ok(cnac.get_hyperlan_peers(peers).unwrap_or_default())
        } else {
            Ok(Default::default())
        }
    }

    async fn get_hyperlan_peer_list_as_server(
        &self,
        implicated_cid: u64,
    ) -> Result<Option<Vec<MutualPeer>>, AccountError> {
        let read = self.clients.read();
        if let Some(cnac) = read.get(&implicated_cid) {
            Ok(cnac.get_hyperlan_peer_mutuals())
        } else {
            Ok(Default::default())
        }
    }

    async fn synchronize_hyperlan_peer_list_as_client(
        &self,
        cnac: &ClientNetworkAccount<R, Fcm>,
        peers: Vec<MutualPeer>,
    ) -> Result<(), AccountError> {
        cnac.synchronize_hyperlan_peer_list(peers);
        Ok(())
    }

    async fn get_byte_map_value(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let read = self.clients.read();
        if let Some(cnac) = read.get(&implicated_cid) {
            let mut lock = cnac.write();
            Ok(lock
                .byte_map
                .entry(peer_cid)
                .or_default()
                .entry(key.to_string())
                .or_default()
                .get(sub_key)
                .cloned())
        } else {
            Ok(None)
        }
    }

    async fn remove_byte_map_value(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let read = self.clients.read();
        if let Some(cnac) = read.get(&implicated_cid) {
            let mut lock = cnac.write();
            Ok(lock
                .byte_map
                .entry(peer_cid)
                .or_default()
                .entry(key.to_string())
                .or_default()
                .remove(sub_key))
        } else {
            Ok(None)
        }
    }

    async fn store_byte_map_value(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let read = self.clients.read();
        if let Some(cnac) = read.get(&implicated_cid) {
            let mut lock = cnac.write();
            Ok(lock
                .byte_map
                .entry(peer_cid)
                .or_default()
                .entry(key.to_string())
                .or_default()
                .insert(sub_key.to_string(), value))
        } else {
            Ok(None)
        }
    }

    async fn get_byte_map_values_by_key(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let read = self.clients.read();
        if let Some(cnac) = read.get(&implicated_cid) {
            let mut lock = cnac.write();
            let map = lock
                .byte_map
                .entry(peer_cid)
                .or_default()
                .entry(key.to_string())
                .or_default()
                .clone();
            Ok(map)
        } else {
            Ok(Default::default())
        }
    }

    async fn remove_byte_map_values_by_key(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let read = self.clients.read();
        if let Some(cnac) = read.get(&implicated_cid) {
            let mut lock = cnac.write();
            let submap = lock
                .byte_map
                .entry(peer_cid)
                .or_default()
                .remove(key)
                .unwrap_or_default();
            Ok(submap)
        } else {
            Ok(Default::default())
        }
    }

    async fn stream_object_to_backend(
        &self,
        source: UnboundedReceiver<Vec<u8>>,
        sink_metadata: Arc<dyn StreamableTargetInformation>,
        status_tx: UnboundedSender<ObjectTransferStatus>,
    ) -> Result<(), AccountError> {
        no_backend_streaming(source, sink_metadata, status_tx).await
    }
}

pub(crate) async fn no_backend_streaming(
    mut source: UnboundedReceiver<Vec<u8>>,
    _sink_metadata: Arc<dyn StreamableTargetInformation>,
    _status_tx: UnboundedSender<ObjectTransferStatus>,
) -> Result<(), AccountError> {
    log::warn!(target: "lusna", "Attempted to stream object to backend, but, streaming is not enabled for this backend");

    while let Some(_) = source.recv().await {
        // exhaust the stream to ensure that the sender does not error out
    }

    Ok(())
}
