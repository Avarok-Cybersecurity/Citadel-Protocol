//! # Redis Backend
//!
//! The Redis backend provides distributed storage for Citadel client accounts and data using Redis.
//! It implements the `BackendConnection` trait and enables scalable, high-performance data storage
//! with support for clustering and replication.
//!
//! ## Features
//!
//! * Distributed storage using Redis
//! * Connection pooling for efficient resource management
//! * Support for Redis clustering
//! * Configurable connection options
//! * Atomic operations for data consistency
//! * Peer relationship management
//! * Byte map storage functionality
//!
//! ## Important Notes
//!
//! * Requires a running Redis server
//! * Supports both standalone and clustered Redis deployments
//! * Implements connection health checks
//! * Handles connection pooling and timeouts
//! * Provides automatic reconnection
//!
//! ## Related Components
//!
//! * `BackendConnection`: The trait implemented for backend storage
//! * `RedisConnectionManager`: Manages Redis connections
//! * `RedisConnectionOptions`: Configuration for Redis connections
//! * `ClientNetworkAccount`: The core data structure being stored
//!

use crate::backend::memory::no_backend_streaming;
use crate::backend::BackendConnection;
use crate::client_account::ClientNetworkAccount;
use crate::misc::{AccountError, CNACMetadata};
use crate::prelude::HYPERLAN_IDX;
use crate::serialization::SyncIO;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use citadel_types::proto::{ObjectTransferStatus, VirtualObjectMetadata};
use citadel_types::user::MutualPeer;
use futures::TryFutureExt;
use mobc::async_trait;
use mobc::Manager;
use mobc::Pool;
use redis_base::{AsyncCommands, Client, ErrorKind, FromRedisValue, ToRedisArgs};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::time::Duration;

/// Backend implementation that stores client data in Redis, providing distributed storage
/// with support for clustering and replication. This backend is suitable for production
/// deployments requiring high availability and scalability.
///
/// The Redis backend manages a connection pool for efficient resource utilization and
/// implements automatic reconnection and health checks. It supports both standalone
/// Redis servers and Redis clusters.
///
/// # Type Parameters
///
/// * `R`: The ratchet type used for encryption
/// * `Fcm`: The ratchet type used for FCM (Firebase Cloud Messaging)
pub(crate) struct RedisBackend<R: Ratchet, Fcm: Ratchet> {
    url: String,
    conn_options: RedisConnectionOptions,
    conn: Option<RedisPool>,
    _pd: PhantomData<(R, Fcm)>,
}

type RedisPool = Pool<RedisConnectionManager>;

/// Configuration options for the Redis connection pool. These options allow fine-tuning
/// of connection management, timeouts, and health checks.
///
/// The connection pool helps manage Redis connections efficiently by maintaining
/// a pool of reusable connections, reducing the overhead of creating new connections
/// for each operation.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
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
    pub clustering_support: bool,
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
    async fn connect(&mut self) -> Result<(), AccountError> {
        let client = redis_base::Client::open(self.url.as_str())
            .map_err(|err| AccountError::msg(err.to_string()))?;

        let manager = RedisConnectionManager { client };
        let mut builder = Pool::builder();

        if let (Some(max_open), Some(max_idle)) = (
            self.conn_options.max_open.as_ref(),
            self.conn_options.max_idle.as_ref(),
        ) {
            if *max_open >= *max_idle {
                return Err(AccountError::msg(
                    "Max open must be greater than or equal to max_idle",
                ));
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

        // ensure that we can establish a connection
        let _ = self.get_conn().await?;

        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError> {
        self.get_conn().await.map(|_| true)
    }

    async fn save_cnac(&self, cnac: &ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        let bytes = cnac.generate_proper_bytes()?;
        let key = get_cid_to_cnac_key();
        let username = cnac.get_username();
        let mut conn = self.get_conn().await?;
        let is_personals_key = if cnac.is_personal() {
            get_personal_status_key()
        } else {
            get_impersonal_status_key()
        };

        redis_base::pipe()
            .atomic()
            // username points to cid key
            .set(get_username_key(&username), cnac.get_cid())
            .ignore()
            // cid key points to bytes
            .hset(key, cnac.get_cid(), bytes)
            .ignore()
            .set(get_cid_to_username_key(cnac.get_cid()), &username)
            .ignore()
            .sadd(is_personals_key, cnac.get_cid())
            .query_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_cnac_by_cid(
        &self,
        cid: u64,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        self.fetch_cnac(cid).await
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        self.get_conn()
            .await?
            .hexists(get_cid_to_cnac_key(), cid)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        // TODO: delete bytemap entries
        let mut conn = self.get_conn().await?;
        redis_base::Script::new(&format!(
            r"
            local username = redis.call('get', KEYS[4])
            local username_key = '{LOCAL_USERNAME_PREFIX}.' .. username
            local peer_cids = redis.call('hvals', KEYS[3])
            redis.call('del', username_key)
            redis.call('del', KEYS[7])
            redis.call('hdel', KEYS[2], KEYS[1])
            redis.call('del', KEYS[3])
            redis.call('del', KEYS[4])
            redis.call('srem', KEYS[5], KEYS[1])
            redis.call('srem', KEYS[6], KEYS[1])

            for _,peer_cid in ipairs(peer_cids)
            do
                local hkey_cid = '{PEER_CID_PREFIX}.' .. peer_cid
                local hkey_username = '{PEER_USERNAME_PREFIX}.' .. peer_cid
                redis.call('hdel', hkey_cid, username)
                redis.call('hdel', hkey_username, KEYS[1])
            end
        ",
        ))
        .key(cid) // 1
        .key(get_cid_to_cnac_key()) // 2
        .key(get_peer_cid_key(cid)) // 3
        .key(get_cid_to_username_key(cid)) // 4
        .key(get_personal_status_key()) // 5
        .key(get_impersonal_status_key()) // 6
        .key(get_peer_username_key(cid)) // 7
        .invoke_async(&mut conn)
        .await
        .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn purge(&self) -> Result<usize, AccountError> {
        let mut conn = self.get_conn().await?;
        redis_base::pipe()
            .atomic()
            .cmd("DBSIZE") // get the count that will be affected
            .cmd("FLUSHDB")
            .ignore()
            .query_async(&mut conn)
            .await
            .map(|ret: Vec<usize>| ret[0])
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_registered_impersonal_cids(
        &self,
        _limit: Option<i32>,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        // TODO: include limit
        self.get_conn()
            .await?
            .smembers(get_impersonal_status_key())
            .await
            .map(|r: Vec<u64>| if r.is_empty() { None } else { Some(r) })
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        self.get(get_cid_to_username_key(cid)).await
    }

    async fn get_full_name_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        match self.get_client_metadata(cid).await? {
            None => Ok(None),
            Some(metadata) => Ok(Some(metadata.full_name)),
        }
    }

    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let mut conn = self.get_conn().await?;
        redis_base::Script::new(
            r"
            local username1 = redis.call('get', KEYS[3])
            local username2 = redis.call('get', KEYS[4])
            redis.call('hset', KEYS[7], KEYS[2], username2)
            redis.call('hset', KEYS[8], KEYS[1], username1)
            redis.call('hset', KEYS[5], username2, KEYS[2])
            redis.call('hset', KEYS[6], username1, KEYS[1])
        ",
        )
        .key(cid0) // 1
        .key(cid1) // 2
        .key(get_cid_to_username_key(cid0)) // 3
        .key(get_cid_to_username_key(cid1)) // 4
        .key(get_peer_cid_key(cid0)) // 5
        .key(get_peer_cid_key(cid1)) // 6
        .key(get_peer_username_key(cid0)) // 7
        .key(get_peer_username_key(cid1)) // 8
        .invoke_async(&mut conn)
        .await
        .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn register_p2p_as_client(
        &self,
        session_cid: u64,
        peer_cid: u64,
        peer_username: String,
    ) -> Result<(), AccountError> {
        let mut conn = self.get_conn().await?;
        redis_base::pipe()
            .atomic()
            .hset(get_peer_username_key(session_cid), peer_cid, &peer_username)
            .ignore()
            .hset(get_peer_cid_key(session_cid), &peer_username, peer_cid)
            .ignore()
            .query_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let mut conn = self.get_conn().await?;
        // TODO: delete bytemap entries for p2p
        redis_base::Script::new(
            r"
            local peer_username1 = redis.call('get', KEYS[5])
            local peer_username2 = redis.call('get', KEYS[6])
            redis.call('hdel', KEYS[3], peer_username2)
            redis.call('hdel', KEYS[4], peer_username1)
            redis.call('hdel', KEYS[7], KEYS[2])
            redis.call('hdel', KEYS[8], KEYS[1])
        ",
        )
        .key(cid0) // 1
        .key(cid1) // 2
        .key(get_peer_cid_key(cid0)) // 3
        .key(get_peer_cid_key(cid1)) // 4
        .key(get_cid_to_username_key(cid0)) // 5
        .key(get_cid_to_username_key(cid1)) // 6
        .key(get_peer_username_key(cid0)) // 7
        .key(get_peer_username_key(cid1)) // 8
        .invoke_async(&mut conn)
        .await
        .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn deregister_p2p_as_client(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        let mut conn = self.get_conn().await?;
        redis_base::Script::new(
            r"
            local peer_username = redis.call('hget', KEYS[4], KEYS[2])
            redis.call('hdel', KEYS[3], peer_username)
            redis.call('hdel', KEYS[4], KEYS[2])
            return peer_username
        ",
        )
        .key(session_cid) // 1
        .key(peer_cid) // 2
        .key(get_peer_cid_key(session_cid)) // 3
        .key(get_peer_username_key(session_cid)) // 4
        .invoke_async(&mut conn)
        .await
        .map_err(|err| AccountError::msg(err.to_string()))
        .map(|peer_username: Option<String>| {
            Some(MutualPeer {
                parent_icid: HYPERLAN_IDX,
                cid: peer_cid,
                username: Some(peer_username?),
            })
        })
    }

    async fn get_hyperlan_peer_list(
        &self,
        session_cid: u64,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        self.get_conn()
            .await?
            .hkeys(get_peer_username_key(session_cid))
            .await
            .map(Some)
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_client_metadata(
        &self,
        session_cid: u64,
    ) -> Result<Option<CNACMetadata>, AccountError> {
        Ok(self
            .fetch_cnac(session_cid)
            .await?
            .map(|r| r.get_metadata()))
    }

    async fn get_clients_metadata(
        &self,
        limit: Option<i32>,
    ) -> Result<Vec<CNACMetadata>, AccountError> {
        // TODO: hard limit in script query, not post-query
        let mut conn = self.get_conn().await?;
        let result: Vec<Vec<u8>> = redis_base::Script::new(
            r"
            local vals = redis.call('hvals', KEYS[1])
            local limit = tonumber(ARGV[1])
            if limit > 0 and limit > table.getn(vals) then
                return unpack(vals, 1, limit)
            end

            return vals
        ",
        )
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

    async fn get_hyperlan_peer_by_cid(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        self.get_conn()
            .await?
            .hget(get_peer_username_key(session_cid), peer_cid)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
            .map(|peer_username: Option<String>| {
                Some(MutualPeer {
                    parent_icid: HYPERLAN_IDX,
                    cid: peer_cid,
                    username: Some(peer_username?),
                })
            })
    }

    async fn hyperlan_peer_exists(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<bool, AccountError> {
        self.get_conn()
            .await?
            .hexists(get_peer_username_key(session_cid), peer_cid)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    #[allow(unused_results)]
    async fn hyperlan_peers_are_mutuals(
        &self,
        session_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<bool>, AccountError> {
        let mut conn = self.get_conn().await?;
        let script = redis_base::Script::new(
            r"
            local ret = {}
            for idx,value in ipairs(KEYS)
            do
                if idx > 1 then
                    ret[#ret+1] = redis.call('hexists', KEYS[1], value)
                end
            end

            return ret
        ",
        );

        let mut script = script.key(get_peer_username_key(session_cid));

        for peer in peers {
            script.key(*peer);
        }

        script
            .invoke_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    #[allow(unused_results)]
    async fn get_hyperlan_peers(
        &self,
        session_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<MutualPeer>, AccountError> {
        let mut conn = self.get_conn().await?;
        let script = redis_base::Script::new(
            r"
            local ret = {}
            for idx,value in ipairs(KEYS)
            do
                if idx > 1 then
                    ret[#ret+1] = redis.call('hget', KEYS[1], value)
                end
            end

            return ret
        ",
        );

        let mut script = script.key(get_peer_username_key(session_cid));

        for peer in peers {
            script.key(*peer);
        }

        script
            .invoke_async(&mut conn)
            .await
            .map(|ret: Vec<String>| {
                ret.into_iter()
                    .zip(peers.iter())
                    .map(|(username, cid)| MutualPeer {
                        parent_icid: HYPERLAN_IDX,
                        cid: *cid,
                        username: Some(username),
                    })
                    .collect()
            })
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_hyperlan_peer_list_as_server(
        &self,
        session_cid: u64,
    ) -> Result<Option<Vec<MutualPeer>>, AccountError> {
        let usernames_map: HashMap<u64, String> = self
            .get_conn()
            .await?
            .hgetall(get_peer_username_key(session_cid)) // get all (peer_cid, username)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))?;

        let mut ret = Vec::with_capacity(usernames_map.len());
        for (cid, username) in usernames_map {
            ret.push(MutualPeer {
                parent_icid: HYPERLAN_IDX,
                cid,
                username: Some(username),
            })
        }

        Ok(Some(ret))
    }

    #[allow(unused_results)]
    async fn synchronize_hyperlan_peer_list_as_client(
        &self,
        cnac: &ClientNetworkAccount<R, Fcm>,
        peers: Vec<MutualPeer>,
    ) -> Result<(), AccountError> {
        let mut conn = self.get_conn().await?;
        let mut pipe = redis_base::pipe();
        let session_cid = cnac.get_cid();
        let peer_cid_key = get_peer_cid_key(session_cid);
        let peer_username_key = get_peer_username_key(session_cid);

        pipe.atomic();

        // delete all local peer records for this user
        let _: () = conn
            .del(&[&peer_cid_key, &peer_username_key])
            .await
            .map_err(|err| AccountError::msg(err.to_string()))?;

        // now, add back everything fresh
        for MutualPeer { cid, username, .. } in peers {
            if let Some(username) = username {
                pipe.hset(&peer_username_key, cid, &username);
                pipe.hset(&peer_cid_key, &username, cid);
            }
        }

        let _: () = pipe
            .query_async(&mut conn)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))?;

        Ok(())
    }

    async fn get_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        self.get_conn()
            .await?
            .hget(get_byte_map_key(session_cid, peer_cid, key), sub_key)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn remove_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let mut conn = self.get_conn().await?;
        let key = get_byte_map_key(session_cid, peer_cid, key);
        redis_base::Script::new(
            r"
            local ret = redis.call('hget', KEYS[1], KEYS[2])
            redis.call('hdel', KEYS[1], KEYS[2])
            return ret
        ",
        )
        .key(key)
        .key(sub_key)
        .invoke_async(&mut conn)
        .await
        .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn store_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let mut conn = self.get_conn().await?;
        let key = get_byte_map_key(session_cid, peer_cid, key);
        redis_base::Script::new(
            r"
            local ret = redis.call('hget', KEYS[1], KEYS[2])
            redis.call('hset', KEYS[1], KEYS[2], ARGV[1])
            return ret
        ",
        )
        .key(key)
        .key(sub_key)
        .arg(value)
        .invoke_async(&mut conn)
        .await
        .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn get_byte_map_values_by_key(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        self.get_conn()
            .await?
            .hgetall(get_byte_map_key(session_cid, peer_cid, key))
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn remove_byte_map_values_by_key(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let mut conn = self.get_conn().await?;
        let key = get_byte_map_key(session_cid, peer_cid, key);
        redis_base::Script::new(
            r"
            local ret = redis.call('hgetall', KEYS[1])
            redis.call('del', KEYS[1])
            return ret
        ",
        )
        .key(key)
        .invoke_async(&mut conn)
        .await
        .map_err(|err| AccountError::msg(err.to_string()))
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

impl<R: Ratchet, Fcm: Ratchet> RedisBackend<R, Fcm> {
    pub(crate) fn new(url: String, conn_options: RedisConnectionOptions) -> Self {
        Self {
            url,
            conn_options,
            conn: None,
            _pd: Default::default(),
        }
    }

    async fn get<K: ToRedisArgs + Send + Sync, RV: FromRedisValue>(
        &self,
        key: K,
    ) -> Result<Option<RV>, AccountError> {
        self.get_with(key, &mut self.get_conn().await?).await
    }

    async fn get_with<K: ToRedisArgs + Send + Sync, RV: FromRedisValue>(
        &self,
        key: K,
        client: &mut redis_base::aio::Connection,
    ) -> Result<Option<RV>, AccountError> {
        client
            .get(key)
            .await
            .map_err(|err| AccountError::msg(err.to_string()))
    }

    async fn fetch_cnac(
        &self,
        cid: u64,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        if let Some(value) = self
            .get_conn()
            .await?
            .hget::<_, _, Option<Vec<u8>>>(get_cid_to_cnac_key(), cid)
            .map_err(|err| AccountError::msg(err.to_string()))
            .await?
        {
            self.cnac_bytes_to_cnac(value).map(Some)
        } else {
            Ok(None)
        }
    }

    fn cnac_bytes_to_cnac(
        &self,
        bytes: Vec<u8>,
    ) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        ClientNetworkAccount::<R, Fcm>::deserialize_from_vector(bytes.as_ref())
    }

    async fn get_conn(&self) -> Result<redis_base::aio::Connection, AccountError> {
        Ok(self
            .conn
            .as_ref()
            .ok_or_else(|| AccountError::msg("Redis client not loaded"))?
            .get()
            .await
            .map_err(|err| AccountError::msg(err.to_string()))?)
        .map(|conn| conn.into_inner())
    }
}

const LOCAL_USERNAME_PREFIX: &str = "username.local";
const LOCAL_CID_PREFIX: &str = "clients";
const LOCAL_CID_TO_USERNAME: &str = "cid.to.username.local";
const PEER_CID_PREFIX: &str = "peers_for.cid";
const PEER_USERNAME_PREFIX: &str = "peers_for.username";
const BYTE_MAP_PREFIX: &str = "byte_map";
const CID_TO_IMPERSONALS: &str = "clients.impersonals";
const CID_TO_PERSONALS: &str = "clients.personals";

fn get_username_key(username: &str) -> String {
    format!("{LOCAL_USERNAME_PREFIX}.{username}")
}

fn get_cid_to_cnac_key() -> &'static str {
    LOCAL_CID_PREFIX
}

fn get_cid_to_username_key(cid: u64) -> String {
    format!("{LOCAL_CID_TO_USERNAME}.{cid}")
}

fn get_peer_cid_key(session_cid: u64) -> String {
    format!("{PEER_CID_PREFIX}.{session_cid}")
}

fn get_peer_username_key(session_cid: u64) -> String {
    format!("{PEER_USERNAME_PREFIX}.{session_cid}")
}

fn get_byte_map_key(session_cid: u64, peer_cid: u64, key: &str) -> String {
    format!("{BYTE_MAP_PREFIX}.{session_cid}.{peer_cid}.{key}",)
}

fn get_impersonal_status_key() -> &'static str {
    CID_TO_IMPERSONALS
}

fn get_personal_status_key() -> &'static str {
    CID_TO_PERSONALS
}
