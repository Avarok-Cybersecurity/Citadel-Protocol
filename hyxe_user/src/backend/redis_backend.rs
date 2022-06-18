use crate::backend::{BackendConnection, PersistenceHandler};
use hyxe_crypt::hyper_ratchet::Ratchet;
use crate::re_imports::DirectoryStore;
use crate::misc::{AccountError, CNACMetadata};
use crate::client_account::{ClientNetworkAccount, MutualPeer};
use std::path::PathBuf;
use std::collections::HashMap;
use parking_lot::Mutex;
use crate::network_account::NetworkAccount;
use hyxe_fs::prelude::SyncIO;
use redis_base::{Client, ErrorKind, AsyncCommands, ToRedisArgs, FromRedisValue};
use mobc::Pool;
use mobc::async_trait;
use mobc::Manager;
use crate::prelude::{ClientNetworkAccountInner, HYPERLAN_IDX};
use std::time::Duration;
use crate::account_loader::load_node_nac;
use futures::StreamExt;

/// Backend struct for redis
pub(crate) struct RedisBackend<R: Ratchet, Fcm: Ratchet> {
    url: String,
    conn_options: RedisConnectionOptions,
    conn: Option<RedisPool>,
    pers: Mutex<Option<PersistenceHandler<R, Fcm>>>,
    local_nac: Option<NetworkAccount<R, Fcm>>
}

type RedisPool = Pool<RedisConnectionManager>;

#[derive(Debug, Default, Clone)]
/// For setting custom options for the internal redis connection pool
pub struct RedisConnectionOptions {
    /// Sets the number of connections. Default 10
    pub max_open: Option<u64>,
    /// Sets the max idle time per connection
    pub max_idle: Option<u64>,
    /// Sets the max lifetime per connection
    pub max_lifetime: Option<Duration>,
    /// Sets the maximum lifetime of connection to be idle in the pool,
    /// resetting the timer when connection is used.
    pub max_idle_lifetime: Option<Duration>,
    /// Sets the get timeout used by the inner pool
    pub get_timeout: Option<Duration>,
    /// Sets the interval how often a connection will be checked when returning
    /// an existing connection from the pool. If set to None, a connection is
    /// checked every time when returning from the pool. Must be used together
    /// with test_on_check_out set to true, otherwise does nothing.
    pub health_check_interval: Option<Duration>,
    /// If true, the health of a connection will be verified via a call to
    /// Manager::check before it is checked out of the pool.
    pub health_check: Option<bool>,
    /// When enabled, will use the clustering algorithms for redis
    pub clustering_support: bool
}

struct RedisConnectionManager {
    client: Client,
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

        let manager = RedisConnectionManager { client };
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

        // ensure that we can establish a connection
        let _ = self.get_conn().await?;

        Ok(())
    }

    async fn post_connect(&self, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<(), AccountError> {
        *self.pers.lock() = Some(persistence_handler.clone());
        self.local_nac.as_ref().unwrap().store_persistence_handler(persistence_handler);
        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError> {
        self.get_conn().await.map(|_| true)
    }

    async fn save_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        let bytes = cnac.generate_proper_bytes()?;
        let key = get_cid_to_cnac_key();
        let username = cnac.get_username();
        let mut conn = self.get_conn().await?;
        redis_base::pipe()
            .atomic()
            // username points to cid key
            .set(get_username_key(&username), cnac.get_cid()).ignore()
            // cid key points to bytes
            .hset(key, cnac.get_cid(), bytes).ignore()
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
        let bytes: Option<Vec<u8>> = redis_base::Script::new(r#"
            local cid = redis.call('get', KEYS[1])
            return redis.call('hget', KEYS[2], cid)
        "#).key(get_username_key(username))
            .key(get_cid_to_cnac_key())
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
        self.get_conn().await?
            .hexists(get_cid_to_cnac_key(), cid)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        // TODO: delete bytemap entries
        let mut conn = self.get_conn().await?;
        redis_base::Script::new(&format!(r"
            local username = redis.call('get', KEYS[4])
            local username_key = '{}.' .. username
            local peers = redis.call('hgetall', KEYS[3])
            redis.call('del', username_key)
            redis.call('hdel', KEYS[2], KEYS[1])
            redis.call('del', KEYS[3])
            redis.call('del', KEYS[4])

            for _,value in ipairs(peers)
            do
                local maybehkey = '{}.' .. value
                redis.call('hdel', maybehkey, KEYS[1])
                redis.call('hdel', maybehkey, username)
            end
        ", LOCAL_USERNAME_PREFIX, PEER_CID_PREFIX))
            .key(cid) // 1
            .key(get_cid_to_cnac_key()) // 2
            .key(get_peer_key(cid)) // 3
            .key(get_cid_to_username_key(cid)) // 4
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
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
            .map(|ret: Vec<usize> | ret[0])
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    fn maybe_generate_cnac_local_save_path(&self, _cid: u64, _is_personal: bool) -> Option<PathBuf> {
        None
    }

    #[allow(unused_results)]
    async fn client_only_generate_possible_cids(&self) -> Result<Vec<u64>, AccountError> {
        let mut conn = self.get_conn().await?;
        let mut pipe = redis_base::pipe();
        let pipe = pipe.atomic();

        let possible_cids = std::iter::repeat_with(||rand::random::<u64>()).take(10).collect::<Vec<u64>>();

        for cid in &possible_cids {
            pipe.exists(*cid);
        }

        pipe.query_async(&mut conn).await.map_err(|err| AccountError::msg(err.to_string()))
            .map(|r: Vec<bool> | possible_cids
                .into_iter()
                .zip(r.into_iter())
                .filter_map(|(cid, exists)| {
                    if exists {
                        None
                    } else {
                        Some(cid)
                    }
                }).collect())
    }

    #[allow(unused_results)]
    async fn find_first_valid_cid(&self, possible_cids: &Vec<u64>) -> Result<Option<u64>, AccountError> {
        let mut conn = self.get_conn().await?;
        let script = redis_base::Script::new(&r#"
            for idx,value in ipairs(KEYS)
            do
                if idx > 1 then
                    local res = redis.call('hexists', KEYS[1], value)
                    if res == 0 then
                        return value
                    end
                end
            end
        "#);

        let mut script = script.prepare_invoke();
        script.key(get_cid_to_cnac_key());

        for cid in possible_cids {
            script.key(cid);
        }

        script
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
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

    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let mut conn = self.get_conn().await?;
        redis_base::Script::new(&r"
            local username1 = redis.call('get', KEYS[3])
            local username2 = redis.call('get', KEYS[4])
            redis.call('hset', KEYS[5], KEYS[2], username2)
            redis.call('hset', KEYS[5], username2, KEYS[2])
            redis.call('hset', KEYS[6], KEYS[1], username1)
            redis.call('hset', KEYS[6], username1, KEYS[1])
        ").key(cid0) // 1
            .key(cid1) // 2
            .key(get_cid_to_username_key(cid0)) // 3
            .key(get_cid_to_username_key(cid1)) // 4
            .key(get_peer_key(cid0)) // 5
            .key(get_peer_key(cid1)) // 6
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn register_p2p_as_client(&self, implicated_cid: u64, peer_cid: u64, peer_username: String) -> Result<(), AccountError> {
        let mut conn = self.get_conn().await?;
        redis_base::pipe()
            .atomic()
            .hset(get_peer_key(implicated_cid), peer_cid, &peer_username).ignore()
            .hset(get_peer_key(implicated_cid), &peer_username, peer_cid).ignore()
            .query_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let mut conn = self.get_conn().await?;
        redis_base::Script::new(&r"
            local peer_username1 = redis.call('get', KEYS[5])
            local peer_username2 = redis.call('get', KEYS[6])
            redis.call('hdel', KEYS[3], KEYS[2])
            redis.call('hdel', KEYS[4], KEYS[1])
            redis.call('hdel', KEYS[3], peer_username2)
            redis.call('hdel', KEYS[4], peer_username1)
        ").key(cid0) // 1
            .key(cid1) // 2
            .key(get_peer_key(cid0)) // 3
            .key(get_peer_key(cid1)) // 4
            .key(get_cid_to_username_key(cid0)) // 5
            .key(get_cid_to_username_key(cid1)) // 6
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn deregister_p2p_as_client(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<MutualPeer>, AccountError> {
        let mut conn = self.get_conn().await?;
        redis_base::Script::new(&r"
            local peer_username = redis.call('hget', KEYS[3], KEYS[2])
            redis.call('hdel', KEYS[3], KEYS[2])
            redis.call('hdel', KEYS[3], peer_username)
            return peer_username
        ").key(implicated_cid) // 1
            .key(peer_cid) // 2
            .key(get_peer_key(implicated_cid)) // 3
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
            .map(|peer_username: Option<String>| {
                Some(
                    MutualPeer {
                        parent_icid: HYPERLAN_IDX,
                        cid: peer_cid,
                        username: Some(peer_username?)
                    }
                )
            })
    }

    async fn get_hyperlan_peer_list(&self, implicated_cid: u64) -> Result<Option<Vec<u64>>, AccountError> {
        self.get_conn().await?
            .hvals(get_peer_key(implicated_cid))
            .await
            .map(|res: Vec<u64>| res)
            .map(Some)
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_client_metadata(&self, implicated_cid: u64) -> Result<Option<CNACMetadata>, AccountError> {
        Ok(self.fetch_cnac(implicated_cid)
            .await?
            .map(|r| r.get_metadata()))
    }

    async fn get_clients_metadata(&self, limit: Option<i32>) -> Result<Vec<CNACMetadata>, AccountError> {
        // TODO: hard limit in script query, not post-query
        let mut conn = self.get_conn().await?;
        let result: Vec<Vec<u8>> = redis_base::Script::new(r"
            local vals = redis.call('hvals', KEYS[1])
            local limit = tonumber(ARGV[1])
            if limit > 0 and limit > table.getn(vals) then
                return unpack(vals, 1, limit)
            end

            return vals
        ")
            .arg(limit.unwrap_or(0))
            .key(get_cid_to_cnac_key())
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))?;


        let mut ret = vec![];
        for bytes in result {
            ret.push(self.cnac_bytes_to_cnac(bytes)?.get_metadata())
        }

        Ok(ret)
    }

    async fn get_hyperlan_peer_by_cid(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<MutualPeer>, AccountError> {
        self.get_conn().await?
            .hget(get_peer_key(implicated_cid), peer_cid)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
            .map(|peer_username: Option<String>| {
                Some(
                    MutualPeer {
                        parent_icid: HYPERLAN_IDX,
                        cid: peer_cid,
                        username: Some(peer_username?)
                    }
                )
            })
    }

    async fn hyperlan_peer_exists(&self, implicated_cid: u64, peer_cid: u64) -> Result<bool, AccountError> {
        self.get_conn().await?
            .hexists(get_peer_key(implicated_cid), peer_cid)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    #[allow(unused_results)]
    async fn hyperlan_peers_are_mutuals(&self, implicated_cid: u64, peers: &Vec<u64>) -> Result<Vec<bool>, AccountError> {
        let mut conn = self.get_conn().await?;
        let script = redis_base::Script::new(&r"
            local ret = {}
            for idx,value in ipairs(KEYS)
            do
                if idx > 1 then
                    ret[#ret+1] = redis.call('hexists', KEYS[1], value)
                end
            end

            return ret
        ");

        let mut script = script.key(get_peer_key(implicated_cid));

        for peer in peers {
            script.key(*peer);
        }

        script
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    #[allow(unused_results)]
    async fn get_hyperlan_peers(&self, implicated_cid: u64, peers: &Vec<u64>) -> Result<Vec<MutualPeer>, AccountError> {
        let mut conn = self.get_conn().await?;
        let script = redis_base::Script::new(&r"
            local ret = {}
            for idx,value in ipairs(KEYS)
            do
                if idx > 1 then
                    ret[#ret+1] = redis.call('hget', KEYS[1], value)
                end
            end

            return ret
        ");

        let mut script = script.key(get_peer_key(implicated_cid));

        for peer in peers {
            script.key(*peer);
        }

        script
            .invoke_async(&mut conn)
            .await
            .map(|ret: Vec<String> | {
                ret.into_iter().zip(peers.into_iter())
                    .map(|(username, cid) | MutualPeer {
                        parent_icid: HYPERLAN_IDX,
                        cid: *cid,
                        username: Some(username)
                    }).collect()
            })
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_hyperlan_peer_by_username(&self, implicated_cid: u64, username: &str) -> Result<Option<MutualPeer>, AccountError> {
        self.get_conn().await?
            .hget(get_peer_key(implicated_cid), username)
            .await
            .map(|peer_cid: Option<u64>| Some(
                MutualPeer {
                    parent_icid: HYPERLAN_IDX,
                    cid: peer_cid?,
                    username: Some(username.to_string())
                }
            ))
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_hyperlan_peer_list_as_server(&self, implicated_cid: u64) -> Result<Option<Vec<MutualPeer>>, AccountError> {
        let mut conn = self.get_conn().await?;
        // TODO: This is wrong. Key may be either string or u64
        let usernames_map: HashMap<u64, String> = redis_base::pipe()
            .atomic()
            .hgetall(get_peer_key(implicated_cid)) // get all (peer_cid, username)
            .query_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))?;

        let mut ret = Vec::with_capacity(usernames_map.len());
        for (cid, username) in usernames_map {
            ret.push(MutualPeer {
                parent_icid: HYPERLAN_IDX,
                cid,
                username: Some(username)
            })
        }

        Ok(Some(ret))
    }

    #[allow(unused_results)]
    async fn synchronize_hyperlan_peer_list_as_client(&self, cnac: &ClientNetworkAccount<R, Fcm>, peers: Vec<MutualPeer>) -> Result<bool, AccountError> {
        let mut conn = self.get_conn().await?;
        let mut pipe = redis_base::pipe();
        let implicated_cid = cnac.get_cid();
        let peer_key = get_peer_key(implicated_cid);

        pipe.atomic();

        // delete all local peer records for this user
        let _: () = conn.del(&peer_key).await.map_err(|err| AccountError::msg(err.to_string()))?;

        // now, add back everything fresh
        for MutualPeer { cid, username, .. } in peers {
            if let Some(username) = username {
                pipe.hset(&peer_key, cid, &username);
                pipe.hset(&peer_key, &username, cid);
            }
        }

        let _: () = pipe.query_async(&mut conn).await.map_err(|err| AccountError::msg(err.to_string()))?;

        // return false to signal no saving
        Ok(false)
    }

    async fn get_byte_map_value(&self, implicated_cid: u64, peer_cid: u64, key: &str, sub_key: &str) -> Result<Option<Vec<u8>>, AccountError> {
        self.get_conn().await?
            .hget(get_byte_map_key(implicated_cid, peer_cid, key), sub_key)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn remove_byte_map_value(&self, implicated_cid: u64, peer_cid: u64, key: &str, sub_key: &str) -> Result<Option<Vec<u8>>, AccountError> {
        let mut conn = self.get_conn().await?;
        let key = get_byte_map_key(implicated_cid, peer_cid, key);
        redis_base::Script::new(r"
            local ret = redis.call('hget', KEYS[1], KEYS[2])
            redis.call('hdel', KEYS[1], KEYS[2])
            return ret
        ").key(key)
            .key(sub_key)
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn store_byte_map_value(&self, implicated_cid: u64, peer_cid: u64, key: &str, sub_key: &str, value: Vec<u8>) -> Result<Option<Vec<u8>>, AccountError> {
        let mut conn = self.get_conn().await?;
        let key = get_byte_map_key(implicated_cid, peer_cid, key);
        redis_base::Script::new(r"
            local ret = redis.call('hget', KEYS[1], KEYS[2])
            redis.call('hset', KEYS[1], KEYS[2], ARGV[1])
            return ret
        ").key(key)
            .key(sub_key)
            .arg(value)
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_byte_map_values_by_key(&self, implicated_cid: u64, peer_cid: u64, key: &str) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        self.get_conn().await?.hgetall(get_byte_map_key(implicated_cid, peer_cid, key)).await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn remove_byte_map_values_by_key(&self, implicated_cid: u64, peer_cid: u64, key: &str) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let mut conn = self.get_conn().await?;
        let key = get_byte_map_key(implicated_cid, peer_cid, key);
        redis_base::Script::new(r"
            local ret = redis.call('hgetall', KEYS[1])
            redis.call('del', KEYS[1])
            return ret
        ").key(key)
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
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

    async fn fetch_cnac(&self, cid: u64) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        if let Some(value) = self.get_conn().await?.hget::<_, _, Option<Vec<u8>>>(get_cid_to_cnac_key(), cid).await? {
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
}

const LOCAL_USERNAME_PREFIX: &str = "username.local";
const LOCAL_CID_PREFIX: &str = "clients";
const LOCAL_CID_TO_USERNAME: &str = "cid.to.username.local";
const PEER_CID_PREFIX: &str = "peers_for.cid";
const BYTE_MAP_PREFIX: &str = "byte_map";

fn get_username_key(username: &str) -> String {
    format!("{}.{}", LOCAL_USERNAME_PREFIX, username)
}

fn get_cid_to_cnac_key() -> &'static str {
    LOCAL_CID_PREFIX
}

fn get_cid_to_username_key(cid: u64) -> String {
    format!("{}.{}", LOCAL_CID_TO_USERNAME, cid)
}

fn get_peer_key(implicated_cid: u64) -> String {
    format!("{}.{}", PEER_CID_PREFIX, implicated_cid)
}

fn get_byte_map_key(implicated_cid: u64, peer_cid: u64, key: &str) -> String {
    format!("{}.{}.{}.{}", BYTE_MAP_PREFIX, implicated_cid, peer_cid, key)
}