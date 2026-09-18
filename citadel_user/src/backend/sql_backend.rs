//! # SQL Backend
//!
//! The SQL backend provides relational database storage for Citadel client accounts and data.
//! It implements the `BackendConnection` trait and supports multiple SQL database variants
//! including MySQL, PostgreSQL, and SQLite.
//!
//! ## Features
//!
//! * Support for multiple SQL database variants
//! * Connection pooling for efficient resource management
//! * Configurable connection options
//! * Automatic schema creation and migration
//! * Atomic database operations
//! * Peer relationship management
//! * Byte map storage functionality
//!
//! ## Important Notes
//!
//! * Requires a running SQL database server (except for SQLite)
//! * Handles database-specific SQL syntax differences
//! * Implements connection pooling and timeouts
//! * Provides automatic schema management
//! * Supports both blob and text storage
//!
//! ## Related Components
//!
//! * `BackendConnection`: The trait implemented for backend storage
//! * `SqlConnectionOptions`: Configuration for SQL connections
//! * `SqlVariant`: Enum for supported SQL database types
//! * `ClientNetworkAccount`: The core data structure being stored
//!

use crate::backend::memory::no_backend_streaming;
use crate::backend::{BackendConnection, BackendType};
use crate::client_account::ClientNetworkAccount;
use crate::misc::{AccountError, CNACMetadata};
use crate::prelude::HYPERLAN_IDX;
use crate::serialization::SyncIO;
use async_trait::async_trait;
use citadel_crypt::ratchets::mono::MonoRatchet;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use citadel_types::proto::{ObjectTransferStatus, VirtualObjectMetadata};
use citadel_types::user::MutualPeer;
use itertools::Itertools;
use sqlx::any::{AnyArguments, AnyPoolOptions, AnyQueryResult, AnyRow, AnyTypeInfoKind};
use sqlx::{AnyPool, Arguments, Column, Executor, Row};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::marker::PhantomData;
use std::ops::DerefMut;
use std::str::FromStr;
use std::time::Duration;

/// Backend implementation that stores client data in SQL databases, supporting multiple
/// database variants including MySQL, PostgreSQL, and SQLite. This backend provides
/// relational storage with ACID properties and efficient querying capabilities.
///
/// The SQL backend manages a connection pool for efficient resource utilization and
/// handles database-specific SQL syntax differences automatically. It supports both
/// blob and text storage formats for different data types.
///
/// # Type Parameters
///
/// * `R`: The ratchet type used for encryption
/// * `Fcm`: The ratchet type used for FCM (Firebase Cloud Messaging)
pub struct SqlBackend<R: Ratchet = StackedRatchet, Fcm: Ratchet = MonoRatchet> {
    url: String,
    conn: Option<AnyPool>,
    variant: SqlVariant,
    opts: SqlConnectionOptions,
    _pd: PhantomData<(R, Fcm)>,
}

/// The supported SQL database variants.
/// Each variant requires specific connection string formatting and SQL syntax.
#[derive(Eq, PartialEq)]
enum SqlVariant {
    /// MySQL/MariaDB database
    MySQL,
    /// PostgreSQL database
    Postgre,
    /// SQLite database
    Sqlite,
}

/// Default value for the CAR (Connection Auto-Reconnect) mode
const CAR_MODE_DEFAULT: bool = false;

/// Configuration options for SQL database connections. These options allow fine-tuning
/// of connection management, pooling behavior, and timeouts.
///
/// The connection pool helps manage database connections efficiently by maintaining
/// a pool of reusable connections, reducing the overhead of creating new connections
/// for each operation.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct SqlConnectionOptions {
    /// The maximum number of connections to keep
    pub max_connections: Option<usize>,
    /// The minimum connections to keep
    pub min_connections: Option<usize>,
    /// After the specified time during the connection process, times out
    pub connect_timeout: Option<Duration>,
    /// How long a connection can remain idle before being closed
    pub idle_timeout: Option<Duration>,
    /// How long a connection can exist (independent to idleness) before being closed
    pub max_lifetime: Option<Duration>,
    /// Create and release (CAR) mode. Holding connections pools may be undesirable for certain platforms with execution restrictions, thus, CAR mode does not keep connections
    pub car_mode: Option<bool>,
}

impl From<&'_ SqlConnectionOptions> for AnyPoolOptions {
    fn from(this: &'_ SqlConnectionOptions) -> AnyPoolOptions {
        let mut ret = AnyPoolOptions::default();

        if let Some(max_connections) = this.max_connections {
            ret = ret.max_connections(max_connections as _);
        }

        if let Some(min_connections) = this.min_connections {
            ret = ret.min_connections(min_connections as _);
        }

        if let Some(connect_timeout) = this.connect_timeout {
            ret = ret.acquire_timeout(connect_timeout);
        }

        ret = ret.idle_timeout(this.idle_timeout);
        ret = ret.max_lifetime(this.max_lifetime);

        if cfg!(feature = "localhost-testing")
            || std::env::var("LOCALHOST_TESTING").unwrap_or_default() == "1"
        {
            log::trace!(target: "citadel", "Reducing connection pool");
            ret = ret.max_connections(1);
            ret = ret.max_lifetime(Duration::from_secs(60));
        }

        ret
    }
}

macro_rules! gen_query {
    ($query:expr, $this:expr, $($bind:expr),+) => {
        if $this.variant == SqlVariant::Sqlite {
            $query$(
                .bind($bind.to_string())
            )+
        } else {
            $query$(
                .bind(u64_into_i64($bind))
            )+
        }
    }
}

#[async_trait]
impl<R: Ratchet, Fcm: Ratchet> BackendConnection<R, Fcm> for SqlBackend<R, Fcm> {
    async fn connect(&mut self) -> Result<(), AccountError> {
        // Setup the drivers
        sqlx::any::install_default_drivers();
        let conn = self.generate_conn().await?;

        if !self.opts.car_mode.unwrap_or(CAR_MODE_DEFAULT) {
            self.conn = Some(conn.clone());
        }

        //let conn = AnyPool::connect_with(&self.url).await?;

        // we use varchar(20) for a u64 since u64::MAX char count = 20

        // The below works on MySql, Postgre, SqLite,
        let bin_type = if self.variant == SqlVariant::Postgre {
            "BYTEA"
        } else {
            "LONGBLOB"
        };

        let cid_type = if self.variant == SqlVariant::Sqlite {
            "TEXT"
        } else {
            "BIGINT"
        };

        // we no longer use bool due to postgresql bug with t/f not being mapped properly
        let cmd = format!("CREATE TABLE IF NOT EXISTS cnacs(cid {cid_type} NOT NULL, is_personal INT, username TEXT, full_name TEXT, creation_date TEXT, bin {bin_type}, PRIMARY KEY (cid))");
        let cmd2 = format!("CREATE TABLE IF NOT EXISTS peers(peer_cid {cid_type}, username TEXT, cid {cid_type}, CONSTRAINT fk_cid FOREIGN KEY (cid) REFERENCES cnacs(cid) ON DELETE CASCADE)");
        let cmd3 = format!("CREATE TABLE IF NOT EXISTS bytemap(cid {cid_type} NOT NULL, peer_cid {cid_type}, id TEXT, sub_id TEXT, bin {bin_type}, CONSTRAINT fk_cid2 FOREIGN KEY (cid) REFERENCES cnacs(cid) ON DELETE CASCADE)");

        // The following commands below allow us to remove entries and automatically remove corresponding values
        let cmd4 = match self.variant {
            SqlVariant::MySQL => {
                let _ = conn
                    .execute("DROP TRIGGER IF EXISTS post_cid_delete")
                    .await
                    .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

                "CREATE TRIGGER post_cid_delete AFTER DELETE ON cnacs FOR EACH ROW DELETE FROM peers WHERE peers.cid = old.cid OR peers.peer_cid = old.cid"
            }

            SqlVariant::Sqlite => {
                let _ = conn
                    .execute("DROP TRIGGER IF EXISTS post_cid_delete")
                    .await
                    .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

                "CREATE TRIGGER post_cid_delete AFTER DELETE ON cnacs FOR EACH ROW BEGIN DELETE FROM peers WHERE peers.cid = old.cid OR peers.peer_cid = old.cid; END"
            }

            SqlVariant::Postgre => {
                let _ = conn
                    .execute("DROP TRIGGER IF EXISTS post_cid_delete ON cnacs")
                    .await
                    .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
                let _ = conn
                    .execute("DROP FUNCTION IF EXISTS post_cid_delete")
                    .await
                    .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

                let create_function = "CREATE OR REPLACE FUNCTION post_cid_delete() RETURNS TRIGGER LANGUAGE PLPGSQL AS $$ BEGIN DELETE FROM peers WHERE peers.cid = old.cid OR peers.peer_cid = old.cid; RETURN NULL; END; $$";
                let _ = conn
                    .execute(create_function)
                    .await
                    .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

                "CREATE TRIGGER post_cid_delete AFTER DELETE ON cnacs FOR EACH ROW EXECUTE PROCEDURE post_cid_delete()"
            }
        };

        // TODO: Create trigger for byte_map

        let joined: String = [cmd, cmd2, cmd3, cmd4.to_string()].join(";");
        let _result = conn
            .execute(&*joined)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError> {
        let conn = &(self.get_conn().await?);
        Ok(!conn.is_closed())
    }

    async fn save_cnac(&self, cnac: &ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);
        // The issue: at endpoints, mutuals are being saved inside CNAC, but not the database. We see here that mutuals are not synced to database
        let bytes = cnac.generate_proper_bytes()?;

        let metadata = cnac.get_metadata();

        // cnacs(cid VARCHAR(20) NOT NULL, is_connected BOOL, is_personal BOOL, fcm_addr TEXT, fcm_api_key TEXT, username VARCHAR({}) UNIQUE, full_name TEXT, creation_date TEXT, bin LONGTEXT, PRIMARY KEY (cid))
        let query = match self.variant {
            SqlVariant::MySQL => {
                // INSERT INTO cnacs VALUES('1') AS new ON DUPLICATE KEY UPDATE cid=new.cid
                "INSERT INTO cnacs VALUES(?, ?, ?, ?, ?, ?) AS new ON DUPLICATE KEY UPDATE cid=new.cid, is_personal=new.is_personal, username=new.username, full_name=new.full_name, creation_date=new.creation_date, bin=new.bin"
            }

            SqlVariant::Postgre | SqlVariant::Sqlite => {
                // INSERT INTO cnacs VALUES('1', 'test') ON CONFLICT(cid) DO UPDATE SET cid=excluded.cid
                "INSERT INTO cnacs VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(cid) DO UPDATE SET cid=excluded.cid, is_personal=excluded.is_personal, username=excluded.username, full_name=excluded.full_name, creation_date=excluded.creation_date, bin=excluded.bin"
            }
        };

        let query = self.format(query);

        let mut args = AnyArguments::default();

        if self.variant == SqlVariant::Sqlite {
            args.add(metadata.cid.to_string()).map_err(|err| {
                citadel_io::error!(citadel_io::ErrorCode::SqlOp, format!("{err:?}"))
            })?;
        } else {
            args.add(u64_into_i64(metadata.cid)).map_err(|err| {
                citadel_io::error!(citadel_io::ErrorCode::SqlOp, format!("{err:?}"))
            })?;
        };

        args.add(metadata.is_personal as i32)
            .map_err(|err| citadel_io::error!(citadel_io::ErrorCode::SqlOp, format!("{err:?}")))?;
        args.add(metadata.username)
            .map_err(|err| citadel_io::error!(citadel_io::ErrorCode::SqlOp, format!("{err:?}")))?;
        args.add(metadata.full_name)
            .map_err(|err| citadel_io::error!(citadel_io::ErrorCode::SqlOp, format!("{err:?}")))?;
        args.add(metadata.creation_date)
            .map_err(|err| citadel_io::error!(citadel_io::ErrorCode::SqlOp, format!("{err:?}")))?;
        args.add(bytes)
            .map_err(|err| citadel_io::error!(citadel_io::ErrorCode::SqlOp, format!("{err:?}")))?;

        let _query = sqlx::query_with(query.as_str(), args)
            .execute(conn)
            .await
            .map_err(|err| citadel_io::error!(citadel_io::ErrorCode::SqlOp, format!("{err:?}")))?;

        Ok(())
    }

    async fn get_cnac_by_cid(
        &self,
        cid: u64,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self.format("SELECT bin FROM cnacs WHERE cid = ? LIMIT 1");
        let query: Option<AnyRow> = gen_query!(sqlx::query(&query), self, cid)
            .fetch_optional(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        self.row_to_cnac(query)
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        let conn = &(self.get_conn().await?);
        let quert = self.format("SELECT cid FROM cnacs WHERE cid = ? LIMIT 1");
        let query: Vec<AnyRow> = gen_query!(sqlx::query(&quert), self, cid)
            .fetch_all(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        Ok(query.len() == 1)
    }

    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self.format("DELETE FROM cnacs WHERE cid = ?");
        let query: AnyQueryResult = gen_query!(sqlx::query(&query), self, cid)
            .execute(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        if query.rows_affected() != 0 {
            Ok(())
        } else {
            Err(AccountError::account_client_non_exists(cid))
        }
    }

    async fn purge(&self) -> Result<usize, AccountError> {
        let conn = &(self.get_conn().await?);
        let _query: AnyQueryResult = sqlx::query("DELETE FROM peers")
            .execute(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        let _query: AnyQueryResult = sqlx::query("DELETE FROM bytemap")
            .execute(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        let query: AnyQueryResult = sqlx::query("DELETE FROM cnacs")
            .execute(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        Ok(query.rows_affected() as usize)
    }

    async fn get_registered_impersonal_cids(
        &self,
        limit: Option<i32>,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        let conn = &(self.get_conn().await?);
        let cmd = limit
            .map(|limit| format!("SELECT cid FROM cnacs WHERE is_personal = ? LIMIT {limit}",))
            .unwrap_or_else(|| "SELECT cid FROM cnacs WHERE is_personal = ?".to_string());
        let query: Vec<AnyRow> = sqlx::query(self.format(cmd).as_str())
            .bind(false as i32)
            .fetch_all(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        let ret: Vec<u64> = query
            .into_iter()
            .filter_map(|r| try_get_cid_from_row(&r, "cid"))
            .collect();

        if ret.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ret))
        }
    }

    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self.format("SELECT username FROM cnacs WHERE cid = ? LIMIT 1");
        let query: Option<AnyRow> = gen_query!(sqlx::query(&query), self, cid)
            .fetch_optional(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        if let Some(row) = query {
            Ok(Some(try_get_blob_as_utf8("username", &row)?))
        } else {
            Ok(None)
        }
    }

    async fn get_full_name_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self.format("SELECT full_name FROM cnacs WHERE cid = ? LIMIT 1");
        let query: Option<AnyRow> = gen_query!(sqlx::query(&query), self, cid)
            .fetch_optional(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        if let Some(row) = query {
            Ok(Some(try_get_blob_as_utf8("full_name", &row)?))
        } else {
            Ok(None)
        }
    }

    // We want to also update the CNACs involved
    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);

        let query = self.format("INSERT INTO peers (peer_cid, cid, username) VALUES (?, ?, (SELECT username FROM cnacs WHERE cid=?)),(?, ?, (SELECT username FROM cnacs WHERE cid=?))");
        let _query = gen_query!(
            sqlx::query(&query),
            self,
            cid0,
            cid1,
            cid0,
            cid1,
            cid0,
            cid1
        )
        .execute(conn)
        .await
        .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        Ok(())
    }

    // We must update the CNAC && the sql database
    async fn register_p2p_as_client(
        &self,
        session_cid: u64,
        peer_cid: u64,
        peer_username: String,
    ) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);
        log::trace!(target: "citadel", "Registering p2p ({} <-> {}) as client", session_cid, peer_cid);
        let query = self.format("INSERT INTO peers (peer_cid, cid, username) VALUES (?, ?, ?)");
        let _query = gen_query!(sqlx::query(&query), self, peer_cid, session_cid)
            .bind(peer_username)
            .execute(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        Ok(())
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);

        let query = self.format(
            "DELETE FROM peers WHERE (peer_cid = ? AND cid = ?) OR (peer_cid = ? AND cid = ?)",
        );
        let _query = gen_query!(sqlx::query(&query), self, cid0, cid1, cid1, cid0)
            .execute(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        Ok(())
    }

    async fn deregister_p2p_as_client(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        let conn = &(self.get_conn().await?);
        let mut tx = conn
            .begin()
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        let query = self.format("SELECT username FROM peers WHERE peer_cid = ? AND cid = ?");
        let row: Option<AnyRow> = gen_query!(sqlx::query(&query), self, peer_cid, session_cid)
            .fetch_optional(tx.deref_mut())
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        if let Some(row) = row {
            let peer_username = try_get_blob_as_utf8("username", &row)?;
            let query = self.format("DELETE FROM peers WHERE peer_cid = ? AND cid = ?");
            let _query = gen_query!(sqlx::query(&query), self, peer_cid, session_cid)
                .execute(tx.deref_mut())
                .await
                .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
            tx.commit()
                .await
                .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

            Ok(Some(MutualPeer {
                cid: peer_cid,
                parent_icid: HYPERLAN_IDX,
                username: Some(peer_username),
            }))
        } else {
            Ok(None)
        }
    }

    async fn get_hyperlan_peer_list(
        &self,
        session_cid: u64,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        let conn = &(self.get_conn().await?);
        // DISTINCT: a pair accepted twice has two rows (see hyperlan_peer_exists),
        // and without it the peer was listed twice.
        let query = self.format("SELECT DISTINCT peer_cid FROM peers WHERE cid = ?");
        let query: Vec<AnyRow> = gen_query!(sqlx::query(&query), self, session_cid)
            .fetch_all(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        let map = query
            .into_iter()
            .filter_map(|row| try_get_cid_from_row(&row, "peer_cid"))
            .collect::<Vec<u64>>();
        if map.is_empty() {
            Ok(None)
        } else {
            Ok(Some(map))
        }
    }

    async fn get_client_metadata(
        &self,
        session_cid: u64,
    ) -> Result<Option<CNACMetadata>, AccountError> {
        let conn = &(self.get_conn().await?);
        // cnacs(cid VARCHAR(20) NOT NULL, is_connected BOOL, is_personal BOOL, username VARCHAR({}) UNIQUE, full_name TEXT, creation_date TEXT, bin LONGTEXT, PRIMARY KEY (cid))
        let query = self.format("SELECT is_personal, username, full_name, creation_date FROM cnacs WHERE cid = ? LIMIT 1");
        let query: Option<AnyRow> = gen_query!(sqlx::query(&query), self, session_cid)
            .fetch_optional(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        if let Some(query) = query {
            let is_personal = self.get_bool(&query, "is_personal")?;
            let username = try_get_blob_as_utf8("username", &query)?;
            let full_name = try_get_blob_as_utf8("full_name", &query)?;
            let creation_date = try_get_blob_as_utf8("creation_date", &query)?;
            Ok(Some(CNACMetadata {
                cid: session_cid,
                is_personal,
                username,
                full_name,
                creation_date,
            }))
        } else {
            Ok(None)
        }
    }

    async fn get_clients_metadata(
        &self,
        limit: Option<i32>,
    ) -> Result<Vec<CNACMetadata>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = if let Some(limit) = limit {
            format!(
                "SELECT cid, is_personal, username, full_name, creation_date FROM cnacs LIMIT {limit}",
            )
        } else {
            "SELECT cid, is_personal, username, full_name, creation_date FROM cnacs".to_string()
        };

        let query: Vec<AnyRow> = sqlx::query(query.as_str())
            .fetch_all(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        Ok(query
            .into_iter()
            .filter_map(|row| {
                let cid = try_get_cid_from_row(&row, "cid")?;

                if cid == 0 {
                    return None;
                }

                let is_personal = self.get_bool(&row, "is_personal").ok()?;
                let username = try_get_blob_as_utf8("username", &row).ok()?;
                let full_name = try_get_blob_as_utf8("full_name", &row).ok()?;
                let creation_date = try_get_blob_as_utf8("creation_date", &row).ok()?;
                Some(CNACMetadata {
                    cid,
                    is_personal,
                    username,
                    full_name,
                    creation_date,
                })
            })
            .collect())
    }

    async fn get_hyperlan_peer_by_cid(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query =
            self.format("SELECT username FROM peers WHERE cid = ? AND peer_cid = ? LIMIT 1");
        let query: Option<AnyRow> = gen_query!(sqlx::query(&query), self, session_cid, peer_cid)
            .fetch_optional(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        if let Some(query) = query {
            match try_get_blob_as_utf8("username", &query) {
                Ok(username) => Ok(Some(MutualPeer {
                    username: Some(username),
                    parent_icid: HYPERLAN_IDX,
                    cid: peer_cid,
                })),

                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    async fn hyperlan_peer_exists(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<bool, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self
            .format("SELECT COUNT(*) as count FROM peers WHERE peer_cid = ? AND cid = ? LIMIT 1");
        let query: AnyRow = gen_query!(sqlx::query(&query), self, peer_cid, session_cid)
            .fetch_one(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        // `>= 1`, not `== 1`. `peers` has no unique constraint on (cid,
        // peer_cid), so a pair accepted twice has two rows, and `== 1` read
        // that registered pair as NOT registered. A missing count still maps
        // to -1 and so to false: an unreadable answer is not "registered".
        Ok(query.try_get::<i64, _>("count").unwrap_or(-1) >= 1)
    }

    async fn hyperlan_peers_are_mutuals(
        &self,
        session_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<bool>, AccountError> {
        if peers.is_empty() {
            return Ok(Vec::new());
        }

        let conn = &(self.get_conn().await?);
        let limit = peers.len();

        let insert = self.construct_arg_insert_any(peers);

        // DISTINCT before the LIMIT. The join returns one row per matching
        // `peers` row, and LIMIT caps it at the number of peers asked about, so a
        // pair accepted twice spent one of those slots on a duplicate and a
        // DIFFERENT, genuinely mutual peer was reported as not mutual.
        let query = self.format(format!("WITH input(peer_cid) AS (VALUES {insert}) SELECT DISTINCT peers.peer_cid FROM input INNER JOIN peers ON input.peer_cid = peers.peer_cid WHERE peers.cid = ? LIMIT {limit}"));
        let query: Vec<AnyRow> = gen_query!(sqlx::query(&query), self, session_cid)
            .fetch_all(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        let results = query
            .into_iter()
            .filter_map(|row| try_get_cid_from_row(&row, "peer_cid"))
            .collect::<Vec<u64>>();

        Ok(peers.iter().map(|cid| results.contains(cid)).collect())
    }

    async fn get_hyperlan_peers(
        &self,
        session_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<MutualPeer>, AccountError> {
        if peers.is_empty() {
            return Ok(Vec::new());
        }

        let conn = &(self.get_conn().await?);
        let limit = peers.len();

        let insert = self.construct_arg_insert_any(peers);

        // DISTINCT before the LIMIT, for the reason in hyperlan_peers_are_mutuals:
        // a duplicated pair returned itself twice and pushed another peer out.
        let query = self.format(format!("WITH input(peer_cid) AS (VALUES {insert}) SELECT DISTINCT peers.peer_cid, peers.username FROM input INNER JOIN peers ON input.peer_cid = peers.peer_cid WHERE peers.cid = ? LIMIT {limit}"));
        let query: Vec<AnyRow> = gen_query!(sqlx::query(&query), self, session_cid)
            .fetch_all(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        Ok(query
            .into_iter()
            .filter_map(|row| {
                let peer_cid = try_get_cid_from_row(&row, "peer_cid")?;
                let peer_username = try_get_blob_as_utf8("username", &row).ok()?;
                Some(MutualPeer {
                    parent_icid: HYPERLAN_IDX,
                    cid: peer_cid,
                    username: Some(peer_username),
                })
            })
            .collect())
    }

    async fn get_hyperlan_peer_list_as_server(
        &self,
        session_cid: u64,
    ) -> Result<Option<Vec<MutualPeer>>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self.format("SELECT peers.peer_cid, peers.username FROM cnacs INNER JOIN peers ON cnacs.cid = peers.cid WHERE peers.cid = ?");
        let query: Vec<AnyRow> = gen_query!(sqlx::query(&query), self, session_cid)
            .fetch_all(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        let mut ret = Vec::with_capacity(query.len());

        for row in query {
            let peer_cid = try_get_cid_from_row(&row, "peer_cid")
                .ok_or_else(|| citadel_io::error!(citadel_io::ErrorCode::SqlDecodePeerCid))?;
            let username = try_get_blob_as_utf8("username", &row)?;
            ret.push(MutualPeer {
                parent_icid: HYPERLAN_IDX,
                cid: peer_cid,
                username: Some(username),
            })
        }

        if ret.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ret))
        }
    }

    // We always return false here, since there's no need for manual saving
    async fn synchronize_hyperlan_peer_list_as_client(
        &self,
        cnac: &ClientNetworkAccount<R, Fcm>,
        peers: Vec<MutualPeer>,
    ) -> Result<(), AccountError> {
        log::trace!(target: "citadel", "Synchronizing peer list for {}", cnac.get_cid());
        if !peers.is_empty() {
            let conn = &(self.get_conn().await?);

            let mut tx = conn
                .begin()
                .await
                .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
            let session_cid = cnac.get_cid();

            let query = self.format("DELETE FROM peers WHERE cid = ?");
            let _query = gen_query!(sqlx::query(&query), self, session_cid)
                .execute(tx.deref_mut())
                .await
                .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
            for MutualPeer { cid, username, .. } in peers {
                let query =
                    self.format("INSERT INTO peers (peer_cid, cid, username) VALUES(?, ?, ?)");
                let _ = gen_query!(sqlx::query(&query), self, cid, session_cid)
                    .bind(username.unwrap_or_else(|| "NULL".into()))
                    .execute(tx.deref_mut())
                    .await
                    .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
            }

            tx.commit()
                .await
                .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        }

        Ok(())
    }

    async fn get_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self.format("SELECT bin FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ? LIMIT 1");
        let row: Option<AnyRow> = gen_query!(sqlx::query(&query), self, session_cid, peer_cid)
            .bind(key)
            .bind(sub_key)
            .fetch_optional(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        if let Some(row) = row {
            match row.try_get::<Vec<u8>, _>("bin") {
                Ok(val) => Ok(Some(val)),

                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    async fn remove_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        // TODO: Optimize this into a single step
        if let Some(value) = self
            .get_byte_map_value(session_cid, peer_cid, key, sub_key)
            .await?
        {
            let conn = &(self.get_conn().await?);
            let query = self.format(
                "DELETE FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ?",
            );
            let _ = gen_query!(sqlx::query(&query), self, session_cid, peer_cid)
                .bind(key)
                .bind(sub_key)
                .execute(conn)
                .await
                .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    async fn store_byte_map_value(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let conn = self.get_conn().await?;
        let get_query = self.format("SELECT bin FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ? LIMIT 1");
        // UPDATE first, INSERT only if it matched nothing.
        //
        // This used to be an unconditional INSERT, and `bytemap` carries no
        // unique constraint on (cid, peer_cid, id, sub_id) -- so every store
        // APPENDED a row and the reads above, which are `LIMIT 1` with no
        // ORDER BY, kept returning the FIRST one written. A byte map key was
        // therefore write-once: the initial value stuck and every later update
        // was invisible, while the table grew a row per write.
        //
        // It was found in production. A workspace's owner was assigned, stored,
        // and then read back empty on the very next request, so the first
        // administrator could never claim the workspace -- twelve rows for one
        // key, four of them carrying the owner that nothing would read. The
        // filesystem backend was unaffected, which is why it went unnoticed:
        // the byte-map tests in citadel_user/tests/primary.rs construct
        // BackendType::Filesystem, so no test ever exercised this path.
        //
        // UPDATE rather than DELETE-then-INSERT for two reasons. It is one
        // atomic statement, so there is no window in which a crash leaves the
        // key with no value at all. And it rewrites EVERY duplicate row a
        // previously-affected store has already accumulated, so those rows
        // become identical and the `LIMIT 1` reads return the right answer
        // immediately -- an existing corrupted store heals on its next write
        // instead of needing a migration.
        let update_query = self.format(
            "UPDATE bytemap SET bin = ? WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ?",
        );
        let set_query = self
            .format("INSERT INTO bytemap (cid, peer_cid, id, sub_id, bin) VALUES (?, ?, ?, ?, ?)");

        let row: Option<AnyRow> = gen_query!(sqlx::query(&get_query), self, session_cid, peer_cid)
            .bind(key)
            .bind(sub_key)
            .fetch_optional(&conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        // `bin` is bound BEFORE the cid pair here, because it is the SET clause
        // and precedes the WHERE -- gen_query! binds the cids in order.
        let updated: AnyQueryResult = gen_query!(
            sqlx::query(&update_query).bind(value.clone()),
            self,
            session_cid,
            peer_cid
        )
        .bind(key)
        .bind(sub_key)
        .execute(&conn)
        .await
        .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        if updated.rows_affected() == 0 {
            let _query = gen_query!(sqlx::query(&set_query), self, session_cid, peer_cid)
                .bind(key)
                .bind(sub_key)
                .bind(value)
                .execute(&conn)
                .await
                .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        }

        if let Some(row) = row {
            match row.try_get::<Vec<u8>, _>("bin") {
                Ok(val) => Ok(Some(val)),

                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    async fn get_byte_map_values_by_key(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self
            .format("SELECT sub_id, bin FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ?");
        let rows: Vec<AnyRow> = gen_query!(sqlx::query(&query), self, session_cid, peer_cid)
            .bind(key)
            .fetch_all(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        let mut ret = HashMap::new();
        for row in rows {
            log::info!(target: "citadel", "Rows: {:?}", row.columns());
            let bin = row
                .try_get::<Vec<u8>, _>("bin")
                .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
            let key = try_get_blob_as_utf8("sub_id", &row)?;
            let _ = ret.insert(key, bin);
        }

        Ok(ret)
    }

    async fn remove_byte_map_values_by_key(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let values = self
            .get_byte_map_values_by_key(session_cid, peer_cid, key)
            .await?;
        let conn = &(self.get_conn().await?);

        let query = self.format("DELETE FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ?");
        let _ = gen_query!(sqlx::query(&query), self, session_cid, peer_cid)
            .bind(key)
            .execute(conn)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;

        Ok(values)
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

impl<R: Ratchet, Fcm: Ratchet> SqlBackend<R, Fcm> {
    async fn get_conn(&self) -> Result<AnyPool, AccountError> {
        if self.opts.car_mode.unwrap_or(CAR_MODE_DEFAULT) {
            self.generate_conn().await
        } else {
            self.conn
                .clone()
                .ok_or_else(|| citadel_io::error!(citadel_io::ErrorCode::SqlConnectionNotLoaded))
        }
    }

    async fn generate_conn(&self) -> Result<AnyPool, AccountError> {
        let opts: AnyPoolOptions = (&self.opts).into();
        log::trace!(target: "citadel", "Generating new connection ...");
        opts.connect(&self.url)
            .await
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))
    }

    fn row_to_cnac(
        &self,
        query: Option<AnyRow>,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        if let Some(row) = query {
            let bin = row
                .try_get::<Vec<u8>, _>("bin")
                .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
            let cnac_inner = ClientNetworkAccount::<R, Fcm>::deserialize_from_owned_vector(bin)?;
            Ok(Some(cnac_inner))
        } else {
            Ok(None)
        }
    }

    fn construct_arg_insert_any(&self, vals: &[u64]) -> String {
        match self.variant {
            SqlVariant::MySQL => self.construct_arg_insert_mysql(vals),
            SqlVariant::Sqlite => self.construct_arg_insert_sqlite(vals),
            SqlVariant::Postgre => self.construct_arg_insert_postgre(vals),
        }
    }

    fn construct_arg_insert_mysql(&self, vals: &[u64]) -> String {
        vals.iter()
            .copied()
            .map(u64_into_i64)
            .map(|val| format!("ROW('{val}')"))
            .join(",")
    }

    fn construct_arg_insert_postgre(&self, vals: &[u64]) -> String {
        vals.iter()
            .copied()
            .map(u64_into_i64)
            .map(|val| format!("({val})"))
            .join(",")
    }

    fn construct_arg_insert_sqlite(&self, vals: &[u64]) -> String {
        vals.iter()
            .copied()
            .map(|val| format!("('{val}')"))
            .join(",")
    }

    fn format<T: Into<String>>(&self, input: T) -> String {
        match self.variant {
            SqlVariant::MySQL | SqlVariant::Sqlite => input.into(),

            SqlVariant::Postgre => {
                let input = input.into();
                let mut output = String::new();
                let mut idx = 0;
                for char in input.chars() {
                    if char != '?' {
                        output.push(char);
                    } else {
                        idx += 1;
                        let val = format!("${idx}");
                        output.push_str(val.as_str());
                    }
                }

                output
            }
        }
    }

    fn get_bool(&self, row: &AnyRow, key: &str) -> Result<bool, AccountError> {
        let int = row
            .try_get::<i32, _>(key)
            .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
        Ok(int != 0)
    }
}

impl<R: Ratchet, Fcm: Ratchet> TryFrom<BackendType> for SqlBackend<R, Fcm> {
    type Error = ();

    fn try_from(t: BackendType) -> Result<Self, ()> {
        let variant = (&t).try_into()?;

        match t {
            BackendType::SQLDatabase(url, opts) => Ok(Self {
                url,
                conn: None,
                variant,
                opts,
                _pd: Default::default(),
            }),

            _ => Err(()),
        }
    }
}

impl TryFrom<&'_ BackendType> for SqlVariant {
    type Error = ();

    fn try_from(this: &BackendType) -> Result<Self, ()> {
        if let BackendType::SQLDatabase(url, ..) = this {
            if url.starts_with("mysql") {
                return Ok(SqlVariant::MySQL);
            }

            if url.starts_with("postgre") {
                return Ok(SqlVariant::Postgre);
            }

            if url.starts_with("sqlite") {
                return Ok(SqlVariant::Sqlite);
            }
        }

        Err(())
    }
}

pub fn try_get_blob_as_utf8(key: &str, row: &AnyRow) -> Result<String, AccountError> {
    match row.column(key).type_info().kind() {
        AnyTypeInfoKind::Text => {
            let blob = row
                .try_get::<String, _>(key)
                .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
            Ok(blob)
        }
        AnyTypeInfoKind::Blob => {
            let blob = row
                .try_get::<Vec<u8>, _>(key)
                .map_err(|e| citadel_io::error!(citadel_io::ErrorCode::SqlOp, e.to_string()))?;
            let blob = String::from_utf8(blob)
                .map_err(|err| citadel_io::error!(citadel_io::ErrorCode::SqlOp, err.to_string()))?;
            Ok(blob)
        }
        res => Err(citadel_io::error!(
            citadel_io::ErrorCode::SqlUnexpectedColumnType,
            citadel_io::Dbg(res)
        )),
    }
}

fn try_get_cid_from_row(row: &AnyRow, key: &str) -> Option<u64> {
    match row.column(key).type_info().kind() {
        AnyTypeInfoKind::Text => {
            let blob = row.try_get::<String, _>(key).ok()?;
            u64::from_str(&blob).ok()
        }
        _ => {
            // Assume BigInt
            let i64 = row.try_get::<i64, _>(key).ok()?;
            Some(i64_into_u64(i64))
        }
    }
}

pub fn i64_into_u64(x: i64) -> u64 {
    (x as u64).wrapping_add(u64::MAX / 2 + 1)
}

pub fn u64_into_i64(x: u64) -> i64 {
    x.wrapping_sub(u64::MAX / 2 + 1) as i64
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "sql", not(coverage)))]
    use citadel_io::tokio;

    #[test]
    fn test_u64_into_i64() {
        assert_eq!(super::u64_into_i64(0), i64::MIN);
        assert_eq!(super::u64_into_i64(u64::MAX), i64::MAX);
    }

    #[test]
    fn test_i64_into_u64() {
        assert_eq!(super::i64_into_u64(i64::MIN), 0);
        assert_eq!(super::i64_into_u64(i64::MAX), u64::MAX);
    }

    /// Storing twice under one key must leave ONE value: the second.
    ///
    /// This is the first test in this crate to drive the byte map through the
    /// SQL backend at all. The existing byte-map coverage in
    /// `citadel_user/tests/primary.rs` constructs `BackendType::Filesystem`,
    /// so the SQL implementation of the same trait was never executed by a
    /// test -- and it did not overwrite. `store_byte_map_value` ran a plain
    /// `INSERT` with no unique constraint on the table, so every write
    /// appended a row, while the reads are `LIMIT 1` with no `ORDER BY` and
    /// kept returning the FIRST. A key was write-once.
    ///
    /// In production that meant a workspace owner could be assigned, stored,
    /// and read back empty on the next request, forever.
    ///
    /// The row count is asserted as well as the value, because the value alone
    /// does not discriminate: a read that happened to return the newest row
    /// would satisfy it while the table still grew without bound.
    #[cfg(all(feature = "sql", not(coverage)))]
    #[tokio::test(flavor = "multi_thread")]
    async fn storing_twice_overwrites_rather_than_appending() {
        use crate::backend::{BackendConnection, BackendType};
        use citadel_crypt::ratchets::stacked::StackedRatchet;

        let dir = std::env::temp_dir().join(format!(
            "citadel-bytemap-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("test.db");
        let url = format!("sqlite://{}?mode=rwc", db.display());

        let mut backend: super::SqlBackend<StackedRatchet, StackedRatchet> =
            super::SqlBackend::try_from(BackendType::sql(url)).unwrap();
        BackendConnection::<StackedRatchet, StackedRatchet>::connect(&mut backend)
            .await
            .unwrap();

        let (cid, peer) = (777u64, 0u64);

        // `bytemap.cid` is a foreign key onto `cnacs`, and SQLite enforces it
        // here, so the row has to exist before any byte map write. Only `cid`
        // is NOT NULL, so a bare row is enough -- this test is about the byte
        // map, not about account serialisation.
        {
            let seed = backend.get_conn().await.unwrap();
            let _seeded = sqlx::query("INSERT INTO cnacs (cid) VALUES (?)")
                .bind(cid.to_string())
                .execute(&seed)
                .await
                .unwrap();
        }

        let _first = backend
            .store_byte_map_value(cid, peer, "k", "sub", b"first".to_vec())
            .await
            .unwrap();
        let previous = backend
            .store_byte_map_value(cid, peer, "k", "sub", b"second".to_vec())
            .await
            .unwrap();

        // The store returns what it replaced, which is still the old contract.
        assert_eq!(previous.as_deref(), Some(&b"first"[..]));

        let got = backend
            .get_byte_map_value(cid, peer, "k", "sub")
            .await
            .unwrap();
        assert_eq!(
            got.as_deref(),
            Some(&b"second"[..]),
            "the second store must be what is read back"
        );

        let conn = backend.get_conn().await.unwrap();
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ?",
        )
        .bind(cid.to_string())
        .bind(peer.to_string())
        .bind("k")
        .bind("sub")
        .fetch_one(&conn)
        .await
        .unwrap();
        assert_eq!(
            rows, 1,
            "one key must hold exactly one row, not a row per write"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pair registered twice is still one registered pair.
    ///
    /// `peers` has no unique constraint on (cid, peer_cid), and
    /// `register_p2p_as_server` inserts on every accepted registration with no
    /// existence check of its own — the only guard is on the CLIENT, in the SDK
    /// prefab, so two peers proposing to each other at the same moment can both
    /// be accepted and write the pair twice. That is the byte-map defect's shape
    /// again, and like it, the duplicate does not merely add a row; it makes
    /// correct answers wrong:
    ///
    ///   - `hyperlan_peer_exists` returned `count == 1`, so two rows read as
    ///     "NOT registered" — and anything that re-registers on that adds a
    ///     third row, and the answer stays wrong for good;
    ///   - `get_hyperlan_peer_list` listed the peer twice;
    ///   - `hyperlan_peers_are_mutuals` and `get_hyperlan_peers` cap their join
    ///     at `LIMIT n` for n peers asked about, so a duplicate spends one of
    ///     those n slots and a DIFFERENT, genuinely mutual peer drops out.
    ///
    /// The third peer (303, registered once) is the discriminating part: an
    /// implementation that only looked at 202 would pass everything else here.
    #[cfg(all(feature = "sql", not(coverage)))]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pair_registered_twice_is_still_one_registered_pair() {
        use crate::backend::{BackendConnection, BackendType};
        use citadel_crypt::ratchets::stacked::StackedRatchet;

        let dir = std::env::temp_dir().join(format!(
            "citadel-peers-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("test.db");
        let url = format!("sqlite://{}?mode=rwc", db.display());

        let mut backend: super::SqlBackend<StackedRatchet, StackedRatchet> =
            super::SqlBackend::try_from(BackendType::sql(url)).unwrap();
        BackendConnection::<StackedRatchet, StackedRatchet>::connect(&mut backend)
            .await
            .unwrap();

        // `peers.cid` is a foreign key onto `cnacs`, and the insert reads each
        // side's username from there, so all three accounts must exist.
        let (me, twice, once) = (101u64, 202u64, 303u64);
        {
            let seed = backend.get_conn().await.unwrap();
            for (cid, name) in [(me, "me"), (twice, "twice"), (once, "once")] {
                let _seeded = sqlx::query("INSERT INTO cnacs (cid, username) VALUES (?, ?)")
                    .bind(cid.to_string())
                    .bind(name)
                    .execute(&seed)
                    .await
                    .unwrap();
            }
        }

        backend.register_p2p_as_server(me, twice).await.unwrap();
        backend.register_p2p_as_server(me, twice).await.unwrap();
        backend.register_p2p_as_server(me, once).await.unwrap();

        assert!(
            backend.hyperlan_peer_exists(me, twice).await.unwrap(),
            "a pair registered twice read as NOT registered"
        );
        assert!(backend.hyperlan_peer_exists(twice, me).await.unwrap());
        assert!(backend.hyperlan_peer_exists(me, once).await.unwrap());

        let mut list = backend.get_hyperlan_peer_list(me).await.unwrap().unwrap();
        list.sort_unstable();
        assert_eq!(list, vec![twice, once], "the peer list repeated a peer");

        assert_eq!(
            backend
                .hyperlan_peers_are_mutuals(me, &[twice, once])
                .await
                .unwrap(),
            vec![true, true],
            "a duplicate row pushed a genuinely mutual peer out of the LIMITed join"
        );

        let mut mutual: Vec<u64> = backend
            .get_hyperlan_peers(me, &[twice, once])
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.cid)
            .collect();
        mutual.sort_unstable();
        assert_eq!(mutual, vec![twice, once]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
