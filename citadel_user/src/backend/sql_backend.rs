use crate::backend::memory::no_backend_streaming;
use crate::backend::{BackendConnection, BackendType};
use crate::client_account::ClientNetworkAccount;
use crate::misc::{AccountError, CNACMetadata};
use crate::prelude::{ClientNetworkAccountInner, HYPERLAN_IDX};
use crate::serialization::SyncIO;
use async_trait::async_trait;
use citadel_crypt::fcm::fcm_ratchet::ThinRatchet;
use citadel_crypt::stacked_ratchet::{Ratchet, StackedRatchet};
use citadel_types::proto::{ObjectTransferStatus, VirtualObjectMetadata};
use citadel_types::user::MutualPeer;
use itertools::Itertools;
use sqlx::any::{AnyArguments, AnyPoolOptions, AnyQueryResult, AnyRow};
use sqlx::postgres::any::AnyTypeInfoKind;
use sqlx::{AnyPool, Arguments, Column, Executor, Row};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::marker::PhantomData;
use std::ops::DerefMut;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// A container for handling db conns
pub struct SqlBackend<R: Ratchet = StackedRatchet, Fcm: Ratchet = ThinRatchet> {
    url: String,
    conn: Option<AnyPool>,
    variant: SqlVariant,
    opts: SqlConnectionOptions,
    _pd: PhantomData<(R, Fcm)>,
}

#[derive(Eq, PartialEq)]
enum SqlVariant {
    MySQL,
    Postgre,
    Sqlite,
}

const CAR_MODE_DEFAULT: bool = false;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
/// Custom connection options
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
                    .await?;

                "CREATE TRIGGER post_cid_delete AFTER DELETE ON cnacs FOR EACH ROW DELETE FROM peers WHERE peers.cid = old.cid OR peers.peer_cid = old.cid"
            }

            SqlVariant::Sqlite => {
                let _ = conn
                    .execute("DROP TRIGGER IF EXISTS post_cid_delete")
                    .await?;

                "CREATE TRIGGER post_cid_delete AFTER DELETE ON cnacs FOR EACH ROW BEGIN DELETE FROM peers WHERE peers.cid = old.cid OR peers.peer_cid = old.cid; END"
            }

            SqlVariant::Postgre => {
                let _ = conn
                    .execute("DROP TRIGGER IF EXISTS post_cid_delete ON cnacs")
                    .await?;
                let _ = conn
                    .execute("DROP FUNCTION IF EXISTS post_cid_delete")
                    .await?;

                let create_function = "CREATE OR REPLACE FUNCTION post_cid_delete() RETURNS TRIGGER LANGUAGE PLPGSQL AS $$ BEGIN DELETE FROM peers WHERE peers.cid = old.cid OR peers.peer_cid = old.cid; RETURN NULL; END; $$";
                let _ = conn.execute(create_function).await?;

                "CREATE TRIGGER post_cid_delete AFTER DELETE ON cnacs FOR EACH ROW EXECUTE PROCEDURE post_cid_delete()"
            }
        };

        // TODO: Create trigger for byte_map

        let joined: String = [cmd, cmd2, cmd3, cmd4.to_string()].join(";");
        let _result = conn.execute(&*joined).await?;

        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError> {
        let conn = &(self.get_conn().await?);
        Ok(!conn.is_closed())
    }

    async fn save_cnac(&self, cnac: &ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);
        // The issue: at endpoints, mutuals are being saved inside CNAC, but not the database. We see here that mutuals are not synced to database
        let serded = cnac.generate_proper_bytes()?;

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
            args.add(metadata.cid.to_string());
        } else {
            args.add(u64_into_i64(metadata.cid));
        };

        args.add(metadata.is_personal as i32);
        args.add(metadata.username);
        args.add(metadata.full_name);
        args.add(metadata.creation_date);
        args.add(serded);

        let _query = sqlx::query_with(query.as_str(), args)
            .execute(conn)
            .await
            .map_err(|err| AccountError::Generic(format!("{err:?}")))?;

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
            .await?;
        self.row_to_cnac(query)
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        let conn = &(self.get_conn().await?);
        let quert = self.format("SELECT cid FROM cnacs WHERE cid = ? LIMIT 1");
        let query: Vec<AnyRow> = gen_query!(sqlx::query(&quert), self, cid)
            .fetch_all(conn)
            .await?;
        Ok(query.len() == 1)
    }

    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self.format("DELETE FROM cnacs WHERE cid = ?");
        let query: AnyQueryResult = gen_query!(sqlx::query(&query), self, cid)
            .execute(conn)
            .await?;

        if query.rows_affected() != 0 {
            Ok(())
        } else {
            Err(AccountError::ClientNonExists(cid))
        }
    }

    async fn purge(&self) -> Result<usize, AccountError> {
        let conn = &(self.get_conn().await?);
        let _query: AnyQueryResult = sqlx::query("DELETE FROM peers").execute(conn).await?;
        let _query: AnyQueryResult = sqlx::query("DELETE FROM bytemap").execute(conn).await?;
        let query: AnyQueryResult = sqlx::query("DELETE FROM cnacs").execute(conn).await?;
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
            .await?;
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
            .await?;

        if let Some(row) = query {
            Ok(Some(try_get_blob_as_utf8("username", &row)?))
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
        .await?;

        Ok(())
    }

    // We must update the CNAC && the sql database
    async fn register_p2p_as_client(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        peer_username: String,
    ) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);
        log::trace!(target: "citadel", "Registering p2p ({} <-> {}) as client", implicated_cid, peer_cid);
        let query = self.format("INSERT INTO peers (peer_cid, cid, username) VALUES (?, ?, ?)");
        let _query = gen_query!(sqlx::query(&query), self, peer_cid, implicated_cid)
            .bind(peer_username)
            .execute(conn)
            .await?;
        Ok(())
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);

        let query = self.format(
            "DELETE FROM peers WHERE (peer_cid = ? AND cid = ?) OR (peer_cid = ? AND cid = ?)",
        );
        let _query = gen_query!(sqlx::query(&query), self, cid0, cid1, cid1, cid0)
            .execute(conn)
            .await?;

        Ok(())
    }

    async fn deregister_p2p_as_client(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        let conn = &(self.get_conn().await?);
        let mut tx = conn.begin().await?;
        let query = self.format("SELECT username FROM peers WHERE peer_cid = ? AND cid = ?");
        let row: Option<AnyRow> = gen_query!(sqlx::query(&query), self, peer_cid, implicated_cid)
            .fetch_optional(tx.deref_mut())
            .await?;

        if let Some(row) = row {
            let peer_username = try_get_blob_as_utf8("username", &row)?;
            let query = self.format("DELETE FROM peers WHERE peer_cid = ? AND cid = ?");
            let _query = gen_query!(sqlx::query(&query), self, peer_cid, implicated_cid)
                .execute(tx.deref_mut())
                .await?;
            tx.commit().await?;

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
        implicated_cid: u64,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self.format("SELECT peer_cid FROM peers WHERE cid = ?");
        let query: Vec<AnyRow> = gen_query!(sqlx::query(&query), self, implicated_cid)
            .fetch_all(conn)
            .await?;

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
        implicated_cid: u64,
    ) -> Result<Option<CNACMetadata>, AccountError> {
        let conn = &(self.get_conn().await?);
        // cnacs(cid VARCHAR(20) NOT NULL, is_connected BOOL, is_personal BOOL, username VARCHAR({}) UNIQUE, full_name TEXT, creation_date TEXT, bin LONGTEXT, PRIMARY KEY (cid)
        let query = self.format("SELECT is_personal, username, full_name, creation_date FROM cnacs WHERE cid = ? LIMIT 1");
        let query: Option<AnyRow> = gen_query!(sqlx::query(&query), self, implicated_cid)
            .fetch_optional(conn)
            .await?;

        if let Some(query) = query {
            let is_personal = self.get_bool(&query, "is_personal")?;
            let username = try_get_blob_as_utf8("username", &query)?;
            let full_name = try_get_blob_as_utf8("full_name", &query)?;
            let creation_date = try_get_blob_as_utf8("creation_date", &query)?;
            Ok(Some(CNACMetadata {
                cid: implicated_cid,
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
        // cnacs(cid VARCHAR(20) NOT NULL, is_connected BOOL, is_personal BOOL,  username VARCHAR({}) UNIQUE, full_name TEXT, creation_date TEXT, bin LONGTEXT, PRIMARY KEY (cid)
        let query = if let Some(limit) = limit {
            format!(
                "SELECT cid, is_personal, username, full_name, creation_date FROM cnacs LIMIT {limit}",
            )
        } else {
            "SELECT cid, is_personal, username, full_name, creation_date FROM cnacs".to_string()
        };

        let query: Vec<AnyRow> = sqlx::query(query.as_str()).fetch_all(conn).await?;

        Ok(query
            .into_iter()
            .filter_map(|row| {
                let cid = try_get_cid_from_row(&row, "cid")?;
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
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query =
            self.format("SELECT username FROM peers WHERE cid = ? AND peer_cid = ? LIMIT 1");
        let query: Option<AnyRow> = gen_query!(sqlx::query(&query), self, implicated_cid, peer_cid)
            .fetch_optional(conn)
            .await?;

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
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<bool, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self
            .format("SELECT COUNT(*) as count FROM peers WHERE peer_cid = ? AND cid = ? LIMIT 1");
        let query: AnyRow = gen_query!(sqlx::query(&query), self, peer_cid, implicated_cid)
            .fetch_one(conn)
            .await?;

        Ok(query.try_get::<i64, _>("count").unwrap_or(-1) == 1)
    }

    async fn hyperlan_peers_are_mutuals(
        &self,
        implicated_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<bool>, AccountError> {
        if peers.is_empty() {
            return Ok(Vec::new());
        }

        let conn = &(self.get_conn().await?);
        let limit = peers.len();

        let insert = self.construct_arg_insert_any(peers);

        let query = self.format(format!("WITH input(peer_cid) AS (VALUES {insert}) SELECT peers.peer_cid FROM input INNER JOIN peers ON input.peer_cid = peers.peer_cid WHERE peers.cid = ? LIMIT {limit}"));
        let query: Vec<AnyRow> = gen_query!(sqlx::query(&query), self, implicated_cid)
            .fetch_all(conn)
            .await?;

        let results = query
            .into_iter()
            .filter_map(|row| try_get_cid_from_row(&row, "peer_cid"))
            .collect::<Vec<u64>>();

        Ok(peers
            .iter()
            .map(|cid| results.iter().any(|peer_cid| *cid == *peer_cid))
            .collect())
    }

    async fn get_hyperlan_peers(
        &self,
        implicated_cid: u64,
        peers: &[u64],
    ) -> Result<Vec<MutualPeer>, AccountError> {
        if peers.is_empty() {
            return Ok(Vec::new());
        }

        let conn = &(self.get_conn().await?);
        let limit = peers.len();

        let insert = self.construct_arg_insert_any(peers);

        let query = self.format(format!("WITH input(peer_cid) AS (VALUES {insert}) SELECT peers.peer_cid, peers.username FROM input INNER JOIN peers ON input.peer_cid = peers.peer_cid WHERE peers.cid = ? LIMIT {limit}"));
        let query: Vec<AnyRow> = gen_query!(sqlx::query(&query), self, implicated_cid)
            .fetch_all(conn)
            .await?;

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
        implicated_cid: u64,
    ) -> Result<Option<Vec<MutualPeer>>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self.format("SELECT peers.peer_cid, peers.username FROM cnacs INNER JOIN peers ON cnacs.cid = peers.cid WHERE peers.cid = ?");
        let query: Vec<AnyRow> = gen_query!(sqlx::query(&query), self, implicated_cid)
            .fetch_all(conn)
            .await?;
        let mut ret = Vec::with_capacity(query.len());

        for row in query {
            let peer_cid = try_get_cid_from_row(&row, "peer_cid")
                .ok_or_else(|| AccountError::Generic("Failed to decode peer cid".into()))?;
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

            let mut tx = conn.begin().await?;
            let implicated_cid = cnac.get_cid();

            let query = self.format("DELETE FROM peers WHERE cid = ?");
            let _query = gen_query!(sqlx::query(&query), self, implicated_cid)
                .execute(tx.deref_mut())
                .await?;
            for MutualPeer { cid, username, .. } in peers {
                let query =
                    self.format("INSERT INTO peers (peer_cid, cid, username) VALUES(?, ?, ?)");
                let _ = gen_query!(sqlx::query(&query), self, cid, implicated_cid)
                    .bind(username.unwrap_or_else(|| "NULL".into()))
                    .execute(tx.deref_mut())
                    .await?;
            }

            tx.commit().await?;
        }

        Ok(())
    }

    async fn get_byte_map_value(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self.format("SELECT bin FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ? LIMIT 1");
        let row: Option<AnyRow> = gen_query!(sqlx::query(&query), self, implicated_cid, peer_cid)
            .bind(key)
            .bind(sub_key)
            .fetch_optional(conn)
            .await?;

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
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        // TODO: Optimize this into a single step
        if let Some(value) = self
            .get_byte_map_value(implicated_cid, peer_cid, key, sub_key)
            .await?
        {
            let conn = &(self.get_conn().await?);
            let query = self.format(
                "DELETE FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ?",
            );
            let _ = gen_query!(sqlx::query(&query), self, implicated_cid, peer_cid)
                .bind(key)
                .bind(sub_key)
                .execute(conn)
                .await?;

            Ok(Some(value))
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
        let conn = self.get_conn().await?;
        let get_query = self.format("SELECT bin FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ? LIMIT 1");
        let set_query = self
            .format("INSERT INTO bytemap (cid, peer_cid, id, sub_id, bin) VALUES (?, ?, ?, ?, ?)");

        let row: Option<AnyRow> =
            gen_query!(sqlx::query(&get_query), self, implicated_cid, peer_cid)
                .bind(key)
                .bind(sub_key)
                .fetch_optional(&conn)
                .await?;

        let _query = gen_query!(sqlx::query(&set_query), self, implicated_cid, peer_cid)
            .bind(key)
            .bind(sub_key)
            .bind(value)
            .execute(&conn)
            .await?;

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
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = self
            .format("SELECT sub_id, bin FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ?");
        let rows: Vec<AnyRow> = gen_query!(sqlx::query(&query), self, implicated_cid, peer_cid)
            .bind(key)
            .fetch_all(conn)
            .await?;

        let mut ret = HashMap::new();
        for row in rows {
            log::info!(target: "citadel", "Rows: {:?}", row.columns());
            let bin = row.try_get::<Vec<u8>, _>("bin")?;
            let key = try_get_blob_as_utf8("sub_id", &row)?;
            let _ = ret.insert(key, bin);
        }

        Ok(ret)
    }

    async fn remove_byte_map_values_by_key(
        &self,
        implicated_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let values = self
            .get_byte_map_values_by_key(implicated_cid, peer_cid, key)
            .await?;
        let conn = &(self.get_conn().await?);

        let query = self.format("DELETE FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ?");
        let _ = gen_query!(sqlx::query(&query), self, implicated_cid, peer_cid)
            .bind(key)
            .execute(conn)
            .await?;

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
                .ok_or_else(|| AccountError::Generic("Connection not loaded".to_string()))
        }
    }

    async fn generate_conn(&self) -> Result<AnyPool, AccountError> {
        let opts: AnyPoolOptions = (&self.opts).into();
        log::trace!(target: "citadel", "Generating new connection ...");
        Ok(opts.connect(&self.url).await?)
    }

    fn row_to_cnac(
        &self,
        query: Option<AnyRow>,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        if let Some(row) = query {
            let bin = row.try_get::<Vec<u8>, _>("bin")?;
            let cnac_inner =
                ClientNetworkAccountInner::<R, Fcm>::deserialize_from_owned_vector(bin)?;
            Ok(Some(cnac_inner.into()))
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
        let int = row.try_get::<i32, _>(key)?;
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
            let blob = row.try_get::<String, _>(key)?;
            Ok(blob)
        }
        AnyTypeInfoKind::Blob => {
            let blob = row.try_get::<Vec<u8>, _>(key)?;
            let blob = String::from_utf8(blob)?;
            Ok(blob)
        }
        res => Err(AccountError::Generic(format!(
            "Expected blob or text, got {res:?}"
        ))),
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
}
