use crate::backend::{BackendConnection, PersistenceHandler};
use hyxe_crypt::hyper_ratchet::Ratchet;
use crate::re_imports::DirectoryStore;
use crate::misc::{AccountError, CNACMetadata};
use crate::client_account::{ClientNetworkAccount, MutualPeer};
use std::path::PathBuf;
use hyxe_crypt::fcm::keys::FcmKeys;
use std::collections::HashMap;
use parking_lot::Mutex;
use crate::network_account::NetworkAccount;
use hyxe_fs::prelude::SyncIO;
use redis_base::{Client, ErrorKind, AsyncCommands, ToRedisArgs, FromRedisValue, LposOptions};
use mobc::{Pool, Connection};
use mobc::async_trait;
use mobc::Manager;
use crate::prelude::ClientNetworkAccountInner;
use std::time::Duration;
use crate::account_loader::load_node_nac;
use futures::StreamExt;
use serde::{Serialize, Deserialize};

/// Backend struct for redis
pub struct RedisBackend<R: Ratchet, Fcm: Ratchet> {
    url: String,
    conn_options: RedisConnectionOptions,
    conn: Option<RedisPool>,
    pers: Mutex<Option<PersistenceHandler<R, Fcm>>>,
    local_nac: Option<NetworkAccount<R, Fcm>>
}

pub type RedisPool = Pool<RedisConnectionManager>;
pub type RedisConn = Connection<RedisConnectionManager>;

#[derive(Debug, Default, Clone)]
pub struct RedisConnectionOptions {
    /// Sets the number of connections. Default 10
    pub max_open: Option<u64>,
    pub max_idle: Option<u64>,
    pub max_lifetime: Option<Duration>,
    pub max_idle_lifetime: Option<Duration>,
    pub get_timeout: Option<Duration>,
    pub health_check_interval: Option<Duration>,
    pub health_check: Option<bool>,
    /// When enabled, will use the clustering algorithms for redis
    pub clustering_support: bool
}

pub struct RedisConnectionManager {
    client: Client,
}

impl RedisConnectionManager {
    pub fn new(c: Client) -> Self {
        Self { client: c }
    }
}

#[async_trait]
impl Manager for RedisConnectionManager {
    type Connection = redis_base::aio::Connection;
    type Error = redis_base::RedisError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let c = self.client.get_async_connection().await?;
        Ok(c)
    }

    async fn check(&self, mut conn: Self::Connection) -> Result<Self::Connection, Self::Error> {
        let pong: String = redis_base::cmd("PING").query_async(&mut conn).await?;
        if pong.as_str() != "PONG" {
            return Err((ErrorKind::ResponseError, "pong response error").into());
        }
        Ok(conn)
    }
}

#[async_trait]
impl<R: Ratchet, Fcm: Ratchet> BackendConnection<R, Fcm> for RedisBackend<R, Fcm> {
    async fn connect(&mut self, directory_store: &DirectoryStore) -> Result<(), AccountError> {
        let client = redis_base::Client::open(self.url.as_str())
            .map_err(|err| AccountError::msg(err.to_string()))?;

        let manager = RedisConnectionManager::new(client);
        let mut builder = Pool::builder();

        if let (Some(max_open), Some(max_idle)) = (self.conn_options.max_open.as_ref(), self.conn_options.max_idle.as_ref()) {
            if *max_open >= *max_idle {
                return Err(AccountError::msg("Max open must be greater than or equal to max_idle"))
            }
        }

        if let Some(val) = self.conn_options.max_open.as_ref() {
            builder = builder.max_open(*val);
        }

        if let Some(val) = self.conn_options.max_idle.as_ref() {
            builder = builder.max_idle(*val);
        }

        if let Some(val) = self.conn_options.max_idle_lifetime.as_ref() {
            builder = builder.max_idle_lifetime(Some(*val));
        }

        if let Some(val) = self.conn_options.get_timeout.as_ref() {
            builder = builder.get_timeout(Some(*val));
        }

        if let Some(val) = self.conn_options.health_check_interval.as_ref() {
            builder = builder.health_check_interval(Some(*val))
        }

        if let Some(val) = self.conn_options.health_check.as_ref() {
            builder = builder.test_on_check_out(*val);
        }

        let pool = builder.build(manager); // panics if max_idle > max_size

        self.conn = Some(pool);
        self.local_nac = Some(load_node_nac(&directory_store)?);

        Ok(())
    }

    async fn post_connect(&self, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<(), AccountError> {
        *self.pers.lock() = Some(persistence_handler.clone());
        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError> {
        self.get_conn().await.map(|_| true)
    }

    async fn save_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        let bytes = cnac.generate_proper_bytes()?;
        let key = get_cid_to_cnac_key(cnac.get_cid());
        let username = cnac.get_username();
        let mut conn = self.get_conn().await?;
        redis_base::pipe()
            .atomic()
            // username points to cid key
            .set(get_username_key(&username), key.clone()).ignore()
            // cid key points to bytes
            .set(key, bytes).ignore()
            .set(get_cid_to_username_key(cnac.get_cid()), &username).ignore()
            .query_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_cnac_by_cid(&self, cid: u64) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        self.fetch_cnac(cid).await
    }

    async fn get_client_by_username(&self, username: &str) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        let mut conn = self.get_conn().await?;
        let bytes: Option<Vec<u8>> = redis_base::Script::new(r"
            return redis.call('get',redis.call('get',KEYS[1]))
        ").key(get_username_key(username))
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))?;

        if let Some(bytes) = bytes {
            self.cnac_bytes_to_cnac(bytes)
                .map(Some)
        } else {
            Ok(None)
        }
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        self.key_exists(get_cid_to_cnac_key(cid)).await
    }

    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        // TODO: delete related entries
        self.delete_entry::<_, Vec<u8>>(get_cid_to_cnac_key(cid)).await
            .map(|_| ())
    }

    async fn save_all(&self) -> Result<(), AccountError> {
        Ok(())
    }

    async fn purge(&self) -> Result<usize, AccountError> {
        let mut conn = self.get_conn().await?;
        redis_base::pipe()
            .atomic()
            .cmd("DBSIZE") // get the count that will be affected
            .cmd("FLUSHDB").ignore()
            .query_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    fn maybe_generate_cnac_local_save_path(&self, _cid: u64, _is_personal: bool) -> Option<PathBuf> {
        None
    }

    async fn client_only_generate_possible_cids(&self) -> Result<Vec<u64>, AccountError> {
        let mut conn = self.get_conn().await?;
        let mut pipe = redis_base::pipe();
        let pipe = pipe.atomic();

        let mut possible_cids = std::iter::repeat_with(||rand::random::<u64>()).take(10).collect::<Vec<u64>>();

        for cid in &possible_cids {
            pipe.exists(*cid);
        }

        let mut ret = vec![];

        if let redis_base::Value::Bulk(vals) = pipe.query_async::<_, redis_base::Value>(&mut conn).await? {
            for (idx, val) in vals.into_iter().enumerate() {
                if let redis_base::Value::Int(0) = val {
                    ret.push(possible_cids[idx])
                }
            }

            Ok(ret)
        } else {
            Err(AccountError::msg("expected Value::Bulk, received unexpected type"))
        }
    }

    async fn find_first_valid_cid(&self, possible_cids: &Vec<u64>) -> Result<Option<u64>, AccountError> {
        let mut conn = self.get_conn().await?;
        let mut pipe = redis_base::pipe();
        let pipe = pipe.atomic();

        for cid in possible_cids {
            pipe.exists(*cid);
        }

        if let redis_base::Value::Bulk(vals) = pipe.query_async::<_, redis_base::Value>(&mut conn).await? {
            for (idx, val) in vals.into_iter().enumerate() {
                if let redis_base::Value::Int(0) = val {
                    return Ok(possible_cids.get(idx).cloned())
                }
            }

            Ok(None)
        } else {
            Ok(None)
        }
    }

    async fn username_exists(&self, username: &str) -> Result<bool, AccountError> {
        self.key_exists(get_username_key(username)).await
    }

    async fn register_cid_in_nac(&self, _cid: u64, _username: &str) -> Result<(), AccountError> {
        // we don't register here since we don't need to store inside the local nac
        Ok(())
    }

    async fn get_registered_impersonal_cids(&self, _limit: Option<i32>) -> Result<Option<Vec<u64>>, AccountError> {
        let mut conn = self.get_conn().await?;
        let result = conn.scan_match::<_, u64>(LOCAL_CID_PREFIX).await
            .map_err(|err| AccountError::msg(err.to_string()))?
            .collect::<Vec<u64>>().await;

        Ok(Some(result))
    }

    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        self.get(get_cid_to_username_key(cid)).await
    }

    async fn get_cid_by_username(&self, username: &str) -> Result<Option<u64>, AccountError> {
        self.get(get_username_key(username)).await
    }

    async fn delete_client_by_username(&self, username: &str) -> Result<(), AccountError> {
        let mut conn = self.get_conn().await?;
        // TODO: delete all related items
        redis_base::Script::new(r"
            redis.call('del', redis.call('get',KEYS[1]));
            redis.call('del', KEYS[1]);
        ").key(get_username_key(username))
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let mut conn = self.get_conn().await?;
        redis_base::Script::new(&format!(r"
            username_1 = redis.call('get', KEYS[3]);
            username_2 = redis.call('get', KEYS[4]);
            redis.call('lpush', KEYS[5], KEYS[2]);
            redis.call('lpush', KEYS[6], KEYS[1]);
            redis.call('lpush', KEYS[7], username2);
            redis.call('lpush', KEYS[8], username1);
        ")).key(cid0) // 1
            .key(cid1) // 2
            .key(get_cid_to_username_key(cid0)) // 3
            .key(get_cid_to_username_key(cid1)) // 4
            .key(get_peer_key(cid0)) // 5
            .key(get_peer_key(cid1)) // 6
            .key(get_peer_username_key(cid0)) // 7
            .key(get_peer_username_key(cid1)) // 8
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn register_p2p_as_client(&self, implicated_cid: u64, peer_cid: u64, peer_username: String) -> Result<(), AccountError> {
        let mut conn = self.get_conn().await?;
        redis_base::pipe()
            .atomic()
            .lpush(get_peer_key(implicated_cid), peer_cid).ignore()
            .lpush(get_peer_username_key(implicated_cid), peer_username)
            .query_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        todo!()
    }

    async fn deregister_p2p_as_client(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<MutualPeer>, AccountError> {
        todo!()
    }

    async fn get_fcm_keys_for_as_server(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<FcmKeys>, AccountError> {
        todo!()
    }

    async fn update_fcm_keys(&self, cnac: &ClientNetworkAccount<R, Fcm>, new_keys: FcmKeys) -> Result<(), AccountError> {
        todo!()
    }

    async fn get_hyperlan_peer_list(&self, implicated_cid: u64) -> Result<Option<Vec<u64>>, AccountError> {
        todo!()
    }

    async fn get_client_metadata(&self, implicated_cid: u64) -> Result<Option<CNACMetadata>, AccountError> {
        Ok(self.fetch_cnac(implicated_cid)
            .await?
            .map(|r| r.get_metadata()))
    }

    async fn get_clients_metadata(&self, limit: Option<i32>) -> Result<Vec<CNACMetadata>, AccountError> {
        todo!()
    }

    async fn get_hyperlan_peer_by_cid(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<MutualPeer>, AccountError> {
        todo!()
    }

    async fn hyperlan_peer_exists(&self, implicated_cid: u64, peer_cid: u64) -> Result<bool, AccountError> {
        self.get_conn().await?
            .lpos(get_peer_key(implicated_cid), peer_cid, LposOptions::default().count(1))
            .await
            .map(|r | r.is_some())
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn hyperlan_peers_are_mutuals(&self, implicated_cid: u64, peers: &Vec<u64>) -> Result<Vec<bool>, AccountError> {
        todo!()
    }

    async fn get_hyperlan_peers(&self, implicated_cid: u64, peers: &Vec<u64>) -> Result<Vec<MutualPeer>, AccountError> {
        todo!()
    }

    async fn get_hyperlan_peer_by_username(&self, implicated_cid: u64, username: &str) -> Result<Option<MutualPeer>, AccountError> {
        todo!()
    }

    async fn get_hyperlan_peer_list_with_fcm_keys_as_server(&self, implicated_cid: u64) -> Result<Option<Vec<(u64, Option<String>, Option<FcmKeys>)>>, AccountError> {
        todo!()
    }

    async fn synchronize_hyperlan_peer_list_as_client(&self, cnac: &ClientNetworkAccount<R, Fcm>, peers: Vec<(u64, Option<String>, Option<FcmKeys>)>) -> Result<bool, AccountError> {
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

    fn local_nac(&self) -> &NetworkAccount<R, Fcm> {
        self.local_nac.as_ref().unwrap()
    }
}

impl<R: Ratchet, Fcm: Ratchet> RedisBackend<R , Fcm> {
    pub(crate) fn new(url: String, conn_options: RedisConnectionOptions) -> Self {
        Self { url, conn_options, conn: None, pers: Mutex::new(None), local_nac: None }
    }

    async fn get<K: ToRedisArgs + Send + Sync, RV: FromRedisValue>(&self, key: K) -> Result<Option<RV>, AccountError> {
        self.get_with(key, &mut self.get_conn().await?).await
    }

    async fn get_with<K: ToRedisArgs + Send + Sync, RV: FromRedisValue>(&self, key: K, client: &mut redis_base::aio::Connection) -> Result<Option<RV>, AccountError> {
        client
            .get(key).await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn set<K: ToRedisArgs + Send + Sync, V: ToRedisArgs + Send + Sync>(&self, key: K, value: V) -> Result<(), AccountError> {
        let mut client = self.get_conn().await?;
        client.set(key, value).await.map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_required(&self, key: &str) -> Result<bytes::Bytes, AccountError> {
        self.get(key).await?.ok_or_else(|| key_does_not_exist(key))
    }


    async fn fetch_cnac(&self, cid: u64) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        if let Some(value) = self.get::<_, Vec<u8>>(get_cid_to_cnac_key(cid)).await? {
            self.cnac_bytes_to_cnac(value)
                .map(Some)
        } else {
            Ok(None)
        }
    }

    fn cnac_bytes_to_cnac(&self, bytes: Vec<u8>) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        let deserialized = ClientNetworkAccountInner::<R, Fcm>::deserialize_from_vector(bytes.as_ref())
            .map_err(|err| AccountError::msg(err.to_string()))?;
        let pers = self.pers.lock().clone().ok_or_else(|| AccountError::msg("Persistence handler is not loaded"))?;

        ClientNetworkAccount::<R, Fcm>::load_safe(deserialized, None, Some(pers))
    }

    async fn get_conn(&self) -> Result<redis_base::aio::Connection, AccountError> {
        Ok(self.conn.as_ref().ok_or_else(|| AccountError::msg("Redis client not loaded"))?
            .get().await
            .map_err(|err| AccountError::msg(err.to_string()))?)
            .map(|conn| conn.into_inner())
    }

    async fn key_exists<K: ToRedisArgs + Send + Sync>(&self, key: K) -> Result<bool, AccountError> {
        self.get_conn().await?
            .exists(key).await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn delete_entry<K: ToRedisArgs + Send + Sync, RV: FromRedisValue>(&self, key: K) -> Result<RV, AccountError> {
        self.get_conn().await?
            .del(key).await
            .map_err(|err| AccountError::msg(err.to_string()))
    }
}

fn key_does_not_exist(key: &str) -> AccountError {
    AccountError::msg(format!("Key '{}' does not exist", key))
}

const LOCAL_USERNAME_PREFIX: &str = "username.local";
const LOCAL_CID_PREFIX: &str = "cid.local";
const LOCAL_CID_TO_USERNAME: &str = "cid.to.username.local";
const PEER_CID_PREFIX: &str = "peers_for.cid";
const PEER_USERNAME_PREFIX: &str = "peers_for.username";

fn get_username_key(username: &str) -> String {
    format!("{}.{}", LOCAL_USERNAME_PREFIX, username)
}

fn get_cid_to_cnac_key(cid: u64) -> String {
    format!("{}.{}", LOCAL_CID_PREFIX, cid)
}

fn get_cid_to_username_key(cid: u64) -> String {
    format!("{}.{}", LOCAL_CID_TO_USERNAME, cid)
}

fn get_peer_key(implicated_cid: u64) -> String {
    format!("{}.{}", PEER_CID_PREFIX, implicated_cid)
}

fn get_peer_username_key(implicated_cid: u64) -> String {
    format!("{}.{}", PEER_USERNAME_PREFIX, implicated_cid)
}