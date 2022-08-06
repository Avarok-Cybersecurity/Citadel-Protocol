use super::utils::StreamableTargetInformation;
use crate::backend::memory::no_backend_streaming;
use crate::backend::utils::ObjectTransferStatus;
use crate::backend::{BackendConnection, BackendType};
use crate::client_account::{ClientNetworkAccount, MutualPeer};
use crate::misc::{AccountError, CNACMetadata, MAX_USERNAME_LENGTH};
use crate::prelude::{ClientNetworkAccountInner, HYPERLAN_IDX};
use crate::serialization::SyncIO;
use async_trait::async_trait;
use hyxe_crypt::fcm::fcm_ratchet::ThinRatchet;
use hyxe_crypt::stacked_ratchet::{Ratchet, StackedRatchet};
use sqlx::any::{AnyArguments, AnyPoolOptions, AnyQueryResult, AnyRow};
use sqlx::{AnyPool, Arguments, Executor, Row};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::marker::PhantomData;
use std::ops::DerefMut;
use std::str::FromStr;
use std::sync::Arc;
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
    /// Catch and release (CAR) mode. Holding connections pools may be undesirbale for certain platforms with execution restrictions, thus, CAR mode does not keep connections
    pub car_mode: Option<bool>,
}

impl Into<AnyPoolOptions> for &'_ SqlConnectionOptions {
    fn into(self) -> AnyPoolOptions {
        let mut ret = AnyPoolOptions::default();

        if let Some(max_connections) = self.max_connections {
            ret = ret.max_connections(max_connections as _);
        }

        if let Some(min_connections) = self.min_connections {
            ret = ret.min_connections(min_connections as _);
        }

        if let Some(connect_timeout) = self.connect_timeout {
            ret = ret.connect_timeout(connect_timeout as _);
        }

        ret = ret.idle_timeout(self.idle_timeout);
        ret = ret.max_lifetime(self.max_lifetime);

        if cfg!(feature = "localhost-testing")
            || std::env::var("LOCALHOST_TESTING").unwrap_or_default() == "1"
        {
            log::trace!(target: "lusna", "Reducing connection pool");
            ret = ret.max_connections(1);
            ret = ret.max_lifetime(Duration::from_secs(60));
        }

        ret
    }
}

#[async_trait]
impl<R: Ratchet, Fcm: Ratchet> BackendConnection<R, Fcm> for SqlBackend<R, Fcm> {
    async fn connect(&mut self) -> Result<(), AccountError> {
        let conn = self.generate_conn().await?;

        if !self.opts.car_mode.unwrap_or(CAR_MODE_DEFAULT) {
            self.conn = Some(conn.clone());
        }

        //let conn = AnyPool::connect_with(&self.url).await?;

        // we use varchar(20) for a u64 since u64::MAX char count = 20

        // The below works on MySql, Postgre, SqLite,
        let bin_type = if self.variant == SqlVariant::Postgre {
            "TEXT"
        } else {
            "LONGTEXT"
        };
        // we no longer use bool due to postgresql bug with t/f not being mapped properly
        let cmd = format!("CREATE TABLE IF NOT EXISTS cnacs(cid VARCHAR(20) NOT NULL, is_personal BOOL, username VARCHAR({}) UNIQUE, full_name TEXT, creation_date TEXT, bin {}, PRIMARY KEY (cid))", MAX_USERNAME_LENGTH, bin_type);
        let cmd2 = format!("CREATE TABLE IF NOT EXISTS peers(peer_cid VARCHAR(20), username VARCHAR({}), cid VARCHAR(20), CONSTRAINT fk_cid FOREIGN KEY (cid) REFERENCES cnacs(cid) ON DELETE CASCADE)", MAX_USERNAME_LENGTH);
        //let cmd3 = format!("CREATE TABLE IF NOT EXISTS bytemap(cid VARCHAR(20) NOT NULL, peer_cid VARCHAR(20), key TEXT, bin TEXT, CONSTRAINT fk_cid FOREIGN KEY (cid) REFERENCES cnacs(cid) ON DELETE CASCADE)");
        let cmd3 = format!("CREATE TABLE IF NOT EXISTS bytemap(cid VARCHAR(20) NOT NULL, peer_cid VARCHAR(20), id TEXT, sub_id TEXT, bin {}, CONSTRAINT fk_cid2 FOREIGN KEY (cid) REFERENCES cnacs(cid) ON DELETE CASCADE)", bin_type);

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
        let serded = base64::encode(cnac.generate_proper_bytes()?);
        log::trace!(target: "lusna", "[CNAC-Sync] Base64 len: {} | sample: {:?} -> {:?}", serded.len(), &serded.as_str()[..10], &serded.as_str()[(serded.len() - 10)..]);

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
        args.add(metadata.cid.to_string());
        args.add(metadata.is_personal);
        args.add(metadata.username);
        args.add(metadata.full_name);
        args.add(metadata.creation_date);
        args.add(serded);

        let _query = sqlx::query_with(query.as_str(), args)
            .execute(conn)
            .await
            .map_err(|err| AccountError::Generic(format!("{:?}", err)))?;

        Ok(())
    }

    async fn get_cnac_by_cid(
        &self,
        cid: u64,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query: Option<AnyRow> = sqlx::query(
            self.format("SELECT bin FROM cnacs WHERE cid = ? LIMIT 1")
                .as_str(),
        )
        .bind(cid.to_string())
        .fetch_optional(conn)
        .await?;
        self.row_to_cnac(query)
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError> {
        let conn = &(self.get_conn().await?);
        let query = sqlx::query(
            self.format("SELECT cid FROM cnacs WHERE cid = ? LIMIT 1")
                .as_str(),
        )
        .bind(cid.to_string())
        .fetch_all(conn)
        .await?;
        Ok(query.len() == 1)
    }

    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);
        let query: AnyQueryResult =
            sqlx::query(self.format("DELETE FROM cnacs WHERE cid = ?").as_str())
                .bind(cid.to_string())
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
            .map(|limit| {
                format!(
                    "SELECT cid FROM cnacs WHERE is_personal = ? LIMIT {}",
                    limit
                )
            })
            .unwrap_or_else(|| "SELECT cid FROM cnacs WHERE is_personal = ?".to_string());
        let query: Vec<AnyRow> = sqlx::query(self.format(cmd).as_str())
            .bind(false)
            .fetch_all(conn)
            .await?;
        let ret: Vec<u64> = query
            .into_iter()
            .filter_map(|r| r.try_get::<String, _>("cid").ok())
            .filter_map(|r| u64::from_str(&r).ok())
            .collect();

        if ret.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ret))
        }
    }

    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError> {
        let conn = &(self.get_conn().await?);
        let query: Option<AnyRow> = sqlx::query(
            self.format("SELECT username FROM cnacs WHERE cid = ? LIMIT 1")
                .as_str(),
        )
        .bind(cid.to_string())
        .fetch_optional(conn)
        .await?;
        if let Some(row) = query {
            Ok(Some(row.try_get::<String, _>("username").unwrap()))
        } else {
            Ok(None)
        }
    }

    // We want to also update the CNACs involved
    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);
        let cid0 = cid0.to_string();
        let cid1 = cid1.to_string();

        let _query = sqlx::query(self.format("INSERT INTO peers (peer_cid, cid, username) VALUES (?, ?, (SELECT username FROM cnacs WHERE cid=?)),(?, ?, (SELECT username FROM cnacs WHERE cid=?))").as_str())
            .bind(cid0.as_str()).bind(cid1.as_str()).bind(cid0.as_str())
            .bind(cid1.as_str()).bind(cid0.as_str()).bind(cid1.as_str())
            .execute(conn).await?;

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
        log::trace!(target: "lusna", "Registering p2p ({} <-> {}) as client", implicated_cid, peer_cid);
        let _query = sqlx::query(
            self.format("INSERT INTO peers (peer_cid, cid, username) VALUES (?, ?, ?)")
                .as_str(),
        )
        .bind(peer_cid.to_string())
        .bind(implicated_cid.to_string())
        .bind(peer_username)
        .execute(conn)
        .await?;
        Ok(())
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let conn = &(self.get_conn().await?);
        let cid0 = cid0.to_string();
        let cid1 = cid1.to_string();

        let _query = sqlx::query(
            self.format(
                "DELETE FROM peers WHERE (peer_cid = ? AND cid = ?) OR (peer_cid = ? AND cid = ?)",
            )
            .as_str(),
        )
        .bind(cid0.as_str())
        .bind(cid1.as_str())
        .bind(cid1.as_str())
        .bind(cid0.as_str())
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
        let row: Option<AnyRow> = sqlx::query(
            self.format("SELECT username FROM peers WHERE peer_cid = ? AND cid = ?")
                .as_str(),
        )
        .bind(peer_cid.to_string())
        .bind(implicated_cid.to_string())
        .fetch_optional(tx.deref_mut())
        .await?;

        if let Some(row) = row {
            let peer_username: String = row.try_get("username")?;
            let _query = sqlx::query(
                self.format("DELETE FROM peers WHERE peer_cid = ? AND cid = ?")
                    .as_str(),
            )
            .bind(peer_cid.to_string())
            .bind(implicated_cid.to_string())
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
        let query: Vec<AnyRow> = sqlx::query(
            self.format("SELECT peer_cid FROM peers WHERE cid = ?")
                .as_str(),
        )
        .bind(implicated_cid.to_string())
        .fetch_all(conn)
        .await?;
        let map = query
            .into_iter()
            .filter_map(|row| row.try_get::<String, _>("peer_cid").ok())
            .filter_map(|val| u64::from_str(val.as_str()).ok())
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
        let query: Option<AnyRow> = sqlx::query(self.format("SELECT is_personal, username, full_name, creation_date FROM cnacs WHERE cid = ? LIMIT 1").as_str()).bind(implicated_cid.to_string()).fetch_optional(conn).await?;

        if let Some(query) = query {
            let is_personal = self.get_bool(&query, "is_personal")?;
            let username = query.try_get("username")?;
            let full_name = query.try_get("full_name")?;
            let creation_date = query.try_get("creation_date")?;
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
                "SELECT cid, is_personal, username, full_name, creation_date FROM cnacs LIMIT {}",
                limit
            )
        } else {
            "SELECT cid, is_personal, username, full_name, creation_date FROM cnacs".to_string()
        };

        let query: Vec<AnyRow> = sqlx::query(query.as_str()).fetch_all(conn).await?;

        Ok(query
            .into_iter()
            .filter_map(|query| {
                let cid = query.try_get::<String, _>("cid").ok()?;
                let cid = u64::from_str(cid.as_str()).ok()?;
                let is_personal = self.get_bool(&query, "is_personal").ok()?;
                let username = query.try_get("username").ok()?;
                let full_name = query.try_get("full_name").ok()?;
                let creation_date = query.try_get("creation_date").ok()?;
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
        let query: Option<AnyRow> = sqlx::query(
            self.format("SELECT username FROM peers WHERE cid = ? AND peer_cid = ? LIMIT 1")
                .as_str(),
        )
        .bind(implicated_cid.to_string())
        .bind(peer_cid.to_string())
        .fetch_optional(conn)
        .await?;

        if let Some(query) = query {
            match query.try_get::<String, _>("username") {
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
        let query: AnyRow = sqlx::query(
            self.format(
                "SELECT COUNT(*) as count FROM peers WHERE peer_cid = ? AND cid = ? LIMIT 1",
            )
            .as_str(),
        )
        .bind(peer_cid.to_string())
        .bind(implicated_cid.to_string())
        .fetch_one(conn)
        .await?;

        Ok(query.try_get::<i64, _>("count").unwrap_or(-1) == 1)
    }

    async fn hyperlan_peers_are_mutuals(
        &self,
        implicated_cid: u64,
        peers: &Vec<u64>,
    ) -> Result<Vec<bool>, AccountError> {
        if peers.is_empty() {
            return Ok(Vec::new());
        }

        let conn = &(self.get_conn().await?);
        let limit = peers.len();

        let insert = self.construct_arg_insert_any(peers);

        let query = format!("WITH input(peer_cid) AS (VALUES {}) SELECT peers.peer_cid FROM input INNER JOIN peers ON input.peer_cid = peers.peer_cid WHERE peers.cid = ? LIMIT {}", insert, limit);

        let query: Vec<AnyRow> = sqlx::query(self.format(query).as_str())
            .bind(implicated_cid.to_string())
            .fetch_all(conn)
            .await?;

        let results = query
            .into_iter()
            .filter_map(|r| r.try_get::<String, _>("peer_cid").ok())
            .filter_map(|v| u64::from_str(v.as_str()).ok())
            .collect::<Vec<u64>>();

        Ok(peers
            .iter()
            .map(|cid| results.iter().any(|peer_cid| *cid == *peer_cid))
            .collect())
    }

    async fn get_hyperlan_peers(
        &self,
        implicated_cid: u64,
        peers: &Vec<u64>,
    ) -> Result<Vec<MutualPeer>, AccountError> {
        if peers.is_empty() {
            return Ok(Vec::new());
        }

        let conn = &(self.get_conn().await?);
        let limit = peers.len();

        let insert = self.construct_arg_insert_any(peers);

        let query = format!("WITH input(peer_cid) AS (VALUES {}) SELECT peers.peer_cid, peers.username FROM input INNER JOIN peers ON input.peer_cid = peers.peer_cid WHERE peers.cid = ? LIMIT {}", insert, limit);

        let query: Vec<AnyRow> = sqlx::query(self.format(query).as_str())
            .bind(implicated_cid.to_string())
            .fetch_all(conn)
            .await?;
        Ok(query
            .into_iter()
            .filter_map(|row| {
                let peer_cid: String = row.try_get("peer_cid").ok()?;
                let peer_cid = u64::from_str(&peer_cid).ok()?;
                let peer_username: String = row.try_get("username").ok()?;
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
        let query: Vec<AnyRow> = sqlx::query(self.format("SELECT peers.peer_cid, peers.username FROM cnacs INNER JOIN peers ON cnacs.cid = peers.cid WHERE peers.cid = ?").as_str()).bind(implicated_cid.to_string()).fetch_all(conn).await?;
        let mut ret = Vec::with_capacity(query.len());

        for row in query {
            let peer_cid = row.try_get::<String, _>("peer_cid")?;
            let peer_cid = u64::from_str(peer_cid.as_str())?;
            let username = row.try_get::<String, _>("username")?;
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
        log::trace!(target: "lusna", "Synchronizing peer list for {}", cnac.get_cid());
        if !peers.is_empty() {
            let conn = &(self.get_conn().await?);

            let mut tx = conn.begin().await?;
            let implicated_cid = cnac.get_cid().to_string();

            let _ = sqlx::query(self.format("DELETE FROM peers WHERE cid = ?").as_str())
                .bind(implicated_cid.as_str())
                .execute(tx.deref_mut())
                .await?;
            for MutualPeer { cid, username, .. } in peers {
                let _ = sqlx::query(
                    self.format("INSERT INTO peers (peer_cid, username, cid) VALUES(?, ?, ?)")
                        .as_str(),
                )
                .bind(cid.to_string())
                .bind(username.unwrap_or_else(|| "NULL".into()))
                .bind(implicated_cid.as_str())
                .execute(tx.deref_mut())
                .await?;
            }

            tx.commit().await?;
            //self.save_cnac(cnac.clone()).await?;
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
        let row: Option<AnyRow> = sqlx::query(self.format("SELECT bin FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ? LIMIT 1").as_str())
            .bind(implicated_cid.to_string())
            .bind(peer_cid.to_string())
            .bind(key)
            .bind(sub_key)
            .fetch_optional(conn).await?;

        if let Some(row) = row {
            match row.try_get::<String, _>("bin") {
                Ok(val) => Ok(Some(base64::decode(val)?)),

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
            let _ = sqlx::query(
                self.format(
                    "DELETE FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ?",
                )
                .as_str(),
            )
            .bind(implicated_cid.to_string())
            .bind(peer_cid.to_string())
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
        let mut tx = conn.begin().await?;
        let bytes_base64 = base64::encode(value);
        let get_query = self.format("SELECT bin FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ? LIMIT 1");
        let set_query = self
            .format("INSERT INTO bytemap (cid, peer_cid, id, sub_id, bin) VALUES (?, ?, ?, ?, ?)");

        let row: Option<AnyRow> = sqlx::query(&get_query)
            .bind(implicated_cid.to_string())
            .bind(peer_cid.to_string())
            .bind(key)
            .bind(sub_key)
            .fetch_optional(&mut tx)
            .await?;

        let _query = sqlx::query(&set_query)
            .bind(implicated_cid.to_string())
            .bind(peer_cid.to_string())
            .bind(key)
            .bind(sub_key)
            .bind(bytes_base64)
            .execute(&mut tx)
            .await?;

        tx.commit().await?;

        if let Some(row) = row {
            match row.try_get::<String, _>("bin") {
                Ok(val) => Ok(Some(base64::decode(val)?)),

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
        let rows: Vec<AnyRow> = sqlx::query(
            self.format(
                "SELECT sub_id, bin FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ?",
            )
            .as_str(),
        )
        .bind(implicated_cid.to_string())
        .bind(peer_cid.to_string())
        .bind(key)
        .fetch_all(conn)
        .await?;

        let mut ret = HashMap::new();
        for row in rows {
            let bin = row.try_get::<String, _>("bin")?;
            let key = row.try_get::<String, _>("sub_id")?;
            let bin = base64::decode(bin)?;
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

        let _ = sqlx::query(
            self.format("DELETE FROM bytemap WHERE cid = ? AND peer_cid = ? AND id = ?")
                .as_str(),
        )
        .bind(implicated_cid.to_string())
        .bind(peer_cid.to_string())
        .bind(key)
        .execute(conn)
        .await?;

        Ok(values)
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

impl<R: Ratchet, Fcm: Ratchet> SqlBackend<R, Fcm> {
    async fn get_conn(&self) -> Result<AnyPool, AccountError> {
        if self.opts.car_mode.unwrap_or(CAR_MODE_DEFAULT) {
            self.generate_conn().await
        } else {
            self.conn
                .clone()
                .ok_or(AccountError::Generic("Connection not loaded".to_string()))
        }
    }

    async fn generate_conn(&self) -> Result<AnyPool, AccountError> {
        let opts: AnyPoolOptions = (&self.opts).into();
        log::trace!(target: "lusna", "Generating new connection ...");
        Ok(opts.connect(&self.url).await?)
    }

    fn row_to_cnac(
        &self,
        query: Option<AnyRow>,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        if let Some(row) = query {
            let bin: String = row.try_get("bin")?;
            log::trace!(target: "lusna", "[CNAC-Load] Base64 len: {} | sample: {:?} -> {:?}", bin.len(), &bin.as_str()[..10], &bin.as_str()[(bin.len() - 10)..]);
            let bin = base64::decode(bin)?;
            let cnac_inner =
                ClientNetworkAccountInner::<R, Fcm>::deserialize_from_owned_vector(bin)?;
            Ok(Some(cnac_inner.into()))
        } else {
            Ok(None)
        }
    }

    fn construct_arg_insert_any(&self, vals: &Vec<u64>) -> String {
        match self.variant {
            SqlVariant::MySQL => self.construct_arg_insert_mysql(vals),

            SqlVariant::Sqlite => self.construct_arg_insert_sqlite(vals),

            SqlVariant::Postgre => self.construct_arg_insert_postgre(vals),
        }
    }

    fn construct_arg_insert_mysql(&self, vals: &Vec<u64>) -> String {
        let mut ret = String::new();
        let len = vals.len();

        for idx in 0..len - 1 {
            ret += &format!("ROW('{}'),", vals[idx]);
        }

        ret += &format!("ROW('{}')", vals[len - 1]);
        ret
    }

    fn construct_arg_insert_postgre(&self, vals: &Vec<u64>) -> String {
        let mut ret = String::new();
        let len = vals.len();

        for idx in 0..len - 1 {
            ret += &format!("('{}'),", vals[idx]);
        }

        ret += &format!("('{}')", vals[len - 1]);
        ret
    }

    fn construct_arg_insert_sqlite(&self, vals: &Vec<u64>) -> String {
        self.construct_arg_insert_postgre(vals)
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
                        let val = format!("${}", idx);
                        output.push_str(val.as_str());
                    }
                }

                output
            }
        }
    }

    fn get_bool(&self, row: &AnyRow, key: &str) -> Result<bool, AccountError> {
        Ok(row.try_get(key)?)
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
        match this {
            BackendType::SQLDatabase(url, ..) => {
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
            _ => {}
        }

        Err(())
    }
}
