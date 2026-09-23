//! [`BackendConnection`] over a [`SqlHost`]. Each method is one host call — one transaction —
//! built in `accounts`, `peers` or `bytemap`; this file only routes to them.

use super::{schema, HostSqlHandle, SqlRow, SqlStatement, SqlValue};
use crate::backend::memory::no_backend_streaming;
use crate::backend::BackendConnection;
use crate::client_account::ClientNetworkAccount;
use crate::misc::{AccountError, CNACMetadata};
use async_trait::async_trait;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use citadel_types::proto::{ObjectTransferStatus, VirtualObjectMetadata};
use citadel_types::user::MutualPeer;
use std::collections::HashMap;
use std::marker::PhantomData;

/// Accounts, peer pairs and byte maps stored through the host's SQL storage.
pub struct HostSqlBackend<R: Ratchet, Fcm: Ratchet> {
    host: HostSqlHandle,
    _pd: PhantomData<fn() -> (R, Fcm)>,
}

impl<R: Ratchet, Fcm: Ratchet> HostSqlBackend<R, Fcm> {
    /// A backend over `host`. Nothing touches the storage until `connect`.
    pub fn new(host: HostSqlHandle) -> Self {
        Self {
            host,
            _pd: PhantomData,
        }
    }

    /// Runs `statements` as one transaction and returns each one's rows.
    pub(super) async fn run(
        &self,
        statements: Vec<SqlStatement>,
    ) -> Result<Vec<Vec<SqlRow>>, AccountError> {
        let expected = statements.len();
        let results = self
            .host
            .0
            .execute(statements)
            .await
            .map_err(super::op_error)?;
        if results.len() != expected {
            return Err(super::op_error(format!(
                "host returned {} result sets for {expected} statements",
                results.len()
            )));
        }
        Ok(results)
    }

    /// Runs one statement and returns its rows.
    pub(super) async fn query(
        &self,
        sql: &'static str,
        params: Vec<SqlValue>,
    ) -> Result<Vec<SqlRow>, AccountError> {
        let mut results = self.run(vec![SqlStatement { sql, params }]).await?;
        Ok(results.remove(0))
    }
}

#[async_trait]
impl<R: Ratchet, Fcm: Ratchet> BackendConnection<R, Fcm> for HostSqlBackend<R, Fcm> {
    async fn connect(&mut self) -> Result<(), AccountError> {
        let ddl = schema::CREATE_TABLES
            .iter()
            .map(|sql| SqlStatement {
                sql,
                params: Vec::new(),
            })
            .collect();
        self.run(ddl).await.map(|_| ())
    }

    async fn is_connected(&self) -> Result<bool, AccountError> {
        Ok(self.query(schema::PING, Vec::new()).await.is_ok())
    }

    async fn save_cnac(&self, cnac: &ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        self.save_account(cnac).await
    }

    async fn get_cnac_by_cid(
        &self,
        cid: u64,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        self.load_account(cid).await
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        self.account_exists(cid).await
    }

    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        self.delete_account(cid).await
    }

    async fn purge(&self) -> Result<usize, AccountError> {
        self.purge_all().await
    }

    async fn get_registered_impersonal_cids(
        &self,
        limit: Option<i32>,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        self.impersonal_cids(limit).await
    }

    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        self.account_text(schema::SELECT_USERNAME, cid).await
    }

    async fn get_full_name_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        self.account_text(schema::SELECT_FULL_NAME, cid).await
    }

    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        self.pair_as_server(cid0, cid1).await
    }

    async fn register_p2p_as_client(
        &self,
        session_cid: u64,
        peer_cid: u64,
        peer_username: String,
    ) -> Result<(), AccountError> {
        self.record_peer(session_cid, peer_cid, peer_username).await
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        self.unpair_as_server(cid0, cid1).await
    }

    async fn deregister_p2p_as_client(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        self.forget_peer(session_cid, peer_cid).await
    }

    async fn get_hyperlan_peer_list(
        &self,
        session_cid: u64,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        let peers = self.peers_of(session_cid).await?;
        Ok(non_empty(peers.into_iter().map(|p| p.cid).collect()))
    }

    async fn get_client_metadata(
        &self,
        session_cid: u64,
    ) -> Result<Option<CNACMetadata>, AccountError> {
        self.metadata(session_cid).await
    }

    async fn get_clients_metadata(
        &self,
        limit: Option<i32>,
    ) -> Result<Vec<CNACMetadata>, AccountError> {
        self.all_metadata(limit).await
    }

    async fn get_hyperlan_peer_by_cid(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        self.peer(session_cid, peer_cid).await
    }

    async fn hyperlan_peer_exists(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<bool, AccountError> {
        Ok(self.peer(session_cid, peer_cid).await?.is_some())
    }

    async fn hyperlan_peers_are_mutuals(
        &self,
        session_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<bool>, AccountError> {
        if peers.is_empty() {
            return Ok(Vec::new());
        }
        let known = self.peers_of(session_cid).await?;
        Ok(peers
            .iter()
            .map(|cid| known.iter().any(|p| p.cid == *cid))
            .collect())
    }

    async fn get_hyperlan_peers(
        &self,
        session_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<MutualPeer>, AccountError> {
        if peers.is_empty() {
            return Ok(Vec::new());
        }
        let known = self.peers_of(session_cid).await?;
        Ok(peers
            .iter()
            .filter_map(|cid| known.iter().find(|p| p.cid == *cid).cloned())
            .collect())
    }

    async fn get_hyperlan_peer_list_as_server(
        &self,
        session_cid: u64,
    ) -> Result<Option<Vec<MutualPeer>>, AccountError> {
        Ok(non_empty(self.peers_of(session_cid).await?))
    }

    async fn synchronize_hyperlan_peer_list_as_client(
        &self,
        cnac: &ClientNetworkAccount<R, Fcm>,
        peers: Vec<MutualPeer>,
    ) -> Result<(), AccountError> {
        self.replace_peers(cnac.get_cid(), peers).await
    }

    async fn get_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        self.entry(session_cid, peer_cid, key, sub_key).await
    }

    async fn remove_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        self.remove_entry(session_cid, peer_cid, key, sub_key).await
    }

    async fn store_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        self.store_entry(session_cid, peer_cid, key, sub_key, value)
            .await
    }

    async fn get_byte_map_values_by_key(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        self.entries(session_cid, peer_cid, key).await
    }

    async fn remove_byte_map_values_by_key(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        self.remove_entries(session_cid, peer_cid, key).await
    }

    async fn stream_object_to_backend(
        &self,
        source: UnboundedReceiver<Vec<u8>>,
        sink_metadata: &VirtualObjectMetadata,
        status_tx: UnboundedSender<ObjectTransferStatus>,
    ) -> Result<(), AccountError> {
        no_backend_streaming(source, sink_metadata, status_tx).await
    }
}

fn non_empty<T>(items: Vec<T>) -> Option<Vec<T>> {
    if items.is_empty() {
        None
    } else {
        Some(items)
    }
}
