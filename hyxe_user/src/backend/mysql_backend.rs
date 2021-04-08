use async_trait::async_trait;
use crate::backend::{BackendConnection, PersistenceHandler, BackendType};
use crate::misc::{AccountError, MAX_USERNAME_LENGTH, CNACMetadata};
use sqlx::{Arguments, Row, AnyPool, Executor};
use hyxe_crypt::hyper_ratchet::{Ratchet, HyperRatchet};
use crate::client_account::{ClientNetworkAccount, MutualPeer};
use std::ops::DerefMut;
use sqlx::any::{AnyArguments, AnyRow, AnyQueryResult};
use crate::prelude::{ClientNetworkAccountInner, NetworkAccount, HYPERLAN_IDX};
use hyxe_fs::io::SyncIO;
use std::path::PathBuf;
use std::str::FromStr;
use crate::re_imports::DirectoryStore;
use crate::account_loader::load_node_nac;
use std::collections::hash_map::RandomState;
use std::sync::Arc;
use std::collections::HashMap;
use crossbeam_utils::sync::ShardedLock;
use hyxe_crypt::fcm::fcm_ratchet::FcmRatchet;
use hyxe_crypt::fcm::keys::FcmKeys;
use std::convert::{TryFrom, TryInto};

/// A container for handling db conns
pub struct SqlBackend<R: Ratchet = HyperRatchet, Fcm: Ratchet = FcmRatchet> {
    url: String,
    conn: Option<AnyPool>,
    local_nac: Option<NetworkAccount<R, Fcm>>,
    variant: SqlVariant
}

#[derive(Eq, PartialEq)]
enum SqlVariant {
    MySQL,
    Postgre,
    Sqlite
}

#[async_trait]
impl<R: Ratchet, Fcm: Ratchet> BackendConnection<R, Fcm> for SqlBackend<R, Fcm> {
    async fn connect(&mut self, directory_store: &DirectoryStore) -> Result<(), AccountError<String>> {
        let conn = AnyPool::connect(&self.url).await?;

        // we use varchar(20) for a u64 since u64::MAX char count = 20

        // The below works on MySql, Postgre, SqLite,
        let bin_type = if self.variant == SqlVariant::Postgre { "TEXT" } else { "LONGTEXT" };
        // we no longer use bool due to postgresql bug with t/f not being mapped properly
        let cmd = format!("CREATE TABLE IF NOT EXISTS cnacs(cid VARCHAR(20) NOT NULL, is_connected BOOL, is_personal BOOL, fcm_addr TEXT, fcm_api_key TEXT, username VARCHAR({}) UNIQUE, full_name TEXT, creation_date TEXT, bin {}, PRIMARY KEY (cid))", MAX_USERNAME_LENGTH, bin_type);
        let cmd2 = format!("CREATE TABLE IF NOT EXISTS peers(peer_cid VARCHAR(20), username VARCHAR({}), cid VARCHAR(20), CONSTRAINT fk_cid FOREIGN KEY (cid) REFERENCES cnacs(cid) ON DELETE CASCADE)", MAX_USERNAME_LENGTH);

        // The following commands below allow us to remove entries and automatically remove corresponding values
        let cmd3 = match self.variant {
            SqlVariant::MySQL => {
                let _ = conn.execute("DROP TRIGGER IF EXISTS post_cid_delete").await?;

                "CREATE TRIGGER post_cid_delete AFTER DELETE ON cnacs FOR EACH ROW DELETE FROM peers WHERE peers.cid = old.cid OR peers.peer_cid = old.cid"
            }

            SqlVariant::Sqlite => {
                let _ = conn.execute("DROP TRIGGER IF EXISTS post_cid_delete").await?;

                "CREATE TRIGGER post_cid_delete AFTER DELETE ON cnacs FOR EACH ROW BEGIN DELETE FROM peers WHERE peers.cid = old.cid OR peers.peer_cid = old.cid; END"
            }

            SqlVariant::Postgre => {
                let _ = conn.execute("DROP TRIGGER IF EXISTS post_cid_delete ON cnacs").await?;
                let _ = conn.execute("DROP FUNCTION IF EXISTS post_cid_delete").await?;

                let create_function = "CREATE OR REPLACE FUNCTION post_cid_delete() RETURNS TRIGGER LANGUAGE PLPGSQL AS $$ BEGIN DELETE FROM peers WHERE peers.cid = old.cid OR peers.peer_cid = old.cid; END; $$";
                let _ = conn.execute(create_function).await?;

                "CREATE TRIGGER post_cid_delete AFTER DELETE ON cnacs FOR EACH ROW EXECUTE PROCEDURE post_cid_delete()"
            }
        };

        {
            let _query0 = sqlx::query(&cmd).execute(&conn).await?;
            let _query1 = sqlx::query(&cmd2).execute(&conn).await?;
            // we must use conn directly to not run into problems with prepared statement
            let _query3 = conn.execute(cmd3).await?;
        }



        self.conn =  Some(conn);
        self.local_nac = Some(load_node_nac(true, directory_store)?);

        Ok(())
    }

    fn post_connect(&self, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<(), AccountError<String>> {
        // we just need to insert the persistence handler inside the nac
        self.local_nac().store_persistence_handler(persistence_handler);
        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError<String>> {
        let conn = self.get_conn()?;
        Ok(!conn.is_closed())
    }

    async fn save_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError<String>> {
        let conn = self.get_conn()?;

        let serded = base64::encode(cnac.generate_proper_bytes()?);

        let keys = cnac.get_fcm_keys();

        let fcm_api_key = keys.as_ref().map(|f| f.api_key.clone());
        let fcm_addr = keys.as_ref().map(|f| f.client_id.clone());
        let metadata = cnac.get_metadata();

        // cnacs(cid VARCHAR(20) NOT NULL, is_connected BOOL, is_personal BOOL, fcm_addr TEXT, fcm_api_key TEXT, username VARCHAR({}) UNIQUE, full_name TEXT, creation_date TEXT, bin LONGTEXT, PRIMARY KEY (cid))
        let query = match self.variant {
            SqlVariant::MySQL => {
                // INSERT INTO cnacs VALUES('1') AS new ON DUPLICATE KEY UPDATE cid=new.cid
                "INSERT INTO cnacs VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) AS new ON DUPLICATE KEY UPDATE cid=new.cid, is_connected=new.is_connected, is_personal=new.is_personal, fcm_addr=new.fcm_addr, fcm_api_key=new.fcm_api_key, username=new.username, full_name=new.full_name, creation_date=new.creation_date, bin=new.bin"
            }

            SqlVariant::Postgre | SqlVariant::Sqlite => {
                // INSERT INTO cnacs VALUES('1', 'test') ON CONFLICT(cid) DO UPDATE SET cid=excluded.cid
                "INSERT INTO cnacs VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(cid) DO UPDATE SET cid=excluded.cid, is_connected=excluded.is_connected, is_personal=excluded.is_personal, fcm_addr=excluded.fcm_addr, fcm_api_key=excluded.fcm_api_key, username=excluded.username, full_name=excluded.full_name, creation_date=excluded.creation_date, bin=excluded.bin"
            }
        };

        let query = self.format(query);

        let mut args = AnyArguments::default();
        args.add(metadata.cid.to_string());
        args.add(false);
        args.add(metadata.is_personal);
        args.add(fcm_addr.unwrap_or_else(||"NULL".into()));
        args.add(fcm_api_key.unwrap_or_else(|| "NULL".into()));
        args.add(metadata.username);
        args.add(metadata.full_name);
        args.add(metadata.creation_date);
        args.add(serded);

        let _query = sqlx::query_with(query.as_str(), args).execute(conn).await.map_err(|err| AccountError::Generic(format!("{:?}",err)))?;

        Ok(())
    }

    async fn get_cnac_by_cid(&self, cid: u64, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError<String>> {
        let conn = self.get_conn()?;
        let query: Option<AnyRow> = sqlx::query(self.format("SELECT bin FROM cnacs WHERE cid = ? LIMIT 1").as_str()).bind(cid.to_string()).fetch_optional(conn).await?;
        self.row_to_cnac(query, persistence_handler)
    }

    async fn get_client_by_username(&self, username: &str, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError<String>> {
        let conn = self.get_conn()?;
        let query: Option<AnyRow> = sqlx::query(self.format("SELECT bin FROM cnacs WHERE username = ? LIMIT 1").as_str()).bind(username).fetch_optional(conn).await?;
        self.row_to_cnac(query, persistence_handler)
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError<String>> {
        let conn = self.get_conn()?;
        let query = sqlx::query(self.format("SELECT cid FROM cnacs WHERE cid = ? LIMIT 1").as_str()).bind(cid.to_string()).fetch_all(conn).await?;
        Ok(query.len() == 1)
    }

    async fn delete_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError<String>> {
        self.delete_cnac_by_cid(cnac.get_cid()).await
    }

    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError<String>> {
        let conn = self.get_conn()?;
        let query: AnyQueryResult = sqlx::query(self.format("DELETE FROM cnacs WHERE cid = ?").as_str()).bind(cid.to_string()).execute(conn).await?;
        if query.rows_affected() != 0 { Ok(()) } else { Err(AccountError::ClientNonExists(cid)) }
    }

    async fn save_all(&self) -> Result<(), AccountError<String>> {
        self.local_nac().save_to_local_fs()?;
        // we don't have to save any cnacs, since those are already saved on the database
        Ok(())
    }

    async fn purge(&self) -> Result<usize, AccountError<String>> {
        let conn = self.get_conn()?;
        let query: AnyQueryResult = sqlx::query("DELETE FROM cnacs").execute(conn).await?;
        Ok(query.rows_affected() as usize)
    }

    async fn client_count(&self) -> Result<usize, AccountError<String>> {
        let conn = self.get_conn()?;
        let query: AnyRow = sqlx::query("SELECT COUNT(*) as count FROM cnacs").fetch_one(conn).await?;
        Ok(query.get::<i64, _>("count") as usize)
    }

    fn maybe_generate_cnac_local_save_path(&self, _cid: u64, _is_personal: bool) -> Option<PathBuf> {
        None
    }

    async fn find_first_valid_cid(&self, possible_cids: &Vec<u64>) -> Result<Option<u64>, AccountError> {
        let conn = self.get_conn()?;

        let len = possible_cids.len();

        if len == 0 {
            return Err(AccountError::Generic("Possible CIDs vector contains no items".to_string()))
        }


        let cmd = match self.variant {
            SqlVariant::MySQL => {
                let insert = self.construct_arg_insert_mysql(possible_cids);
                format!("SELECT Column_0 as cid FROM (SELECT * FROM (VALUES {}) TMP) VALS LEFT JOIN cnacs ON VALS.Column_0 = cnacs.cid WHERE cnacs.cid IS NULL LIMIT 1", insert)
            },

            SqlVariant::Postgre => {
                let insert = self.construct_arg_insert_postgre(possible_cids);
                format!("SELECT Column_0 as cid FROM (SELECT * FROM (VALUES {}) TMP) as VALS(Column_0) LEFT JOIN cnacs ON VALS.Column_0 = cnacs.cid WHERE cnacs.cid IS NULL LIMIT 1", insert)
            }

            SqlVariant::Sqlite => {
                let insert = self.construct_arg_insert_sqlite(possible_cids);
                // Note: the below works with the above 2 as well
                format!("WITH temptable(column_0) as (VALUES {}) SELECT column_0 as cid FROM temptable LEFT JOIN cnacs ON temptable.column_0 = cnacs.cid WHERE cnacs.cid IS NULL LIMIT 1", insert)
            }
        };

        let query: AnyRow = sqlx::query(cmd.as_str()).fetch_one(conn).await?;

        if let Ok(val) = query.try_get::<String, _>("cid") {
            let available_cid = u64::from_str(&val)?;
            Ok(Some(available_cid))
        } else {
            Ok(None)
        }
    }

    async fn username_exists(&self, username: &str) -> Result<bool, AccountError> {
        let conn = self.get_conn()?;
        let query: AnyRow = sqlx::query(self.format("SELECT COUNT(1) as count FROM cnacs where username = ?").as_str()).bind(username).fetch_one(conn).await?;
        Ok(query.get::<i64, _>("count") == 1)
    }

    async fn register_cid_in_nac(&self, _cid: u64, _username: &str) -> Result<(), AccountError<String>> {
        // we don't register here since we don't need to store inside the local nac
        Ok(())
    }

    async fn get_registered_impersonal_cids(&self, limit: Option<i32>) -> Result<Option<Vec<u64>>, AccountError<String>> {
        let conn = self.get_conn()?;
        let cmd = limit.map(|limit| format!("SELECT cid FROM cnacs WHERE is_personal = ? LIMIT {}", limit)).unwrap_or_else(|| "SELECT cid FROM cnacs WHERE is_personal = ?".to_string());
        let query: Vec<AnyRow> = sqlx::query(self.format(cmd).as_str()).bind(false).fetch_all(conn).await?;
        let ret: Vec<u64> = query.into_iter().filter_map(|r| r.try_get::<String,_>("cid").ok()).filter_map(|r| u64::from_str(&r).ok()).collect();

        if ret.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ret))
        }
    }

    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError<String>> {
        let conn = self.get_conn()?;
        let query: Option<AnyRow> = sqlx::query(self.format("SELECT username FROM cnacs WHERE cid = ? LIMIT 1").as_str()).bind(cid.to_string()).fetch_optional(conn).await?;
        if let Some(row) = query {
            Ok(Some(row.try_get::<String, _>("username").unwrap()))
        } else {
            Ok(None)
        }
    }

    async fn get_cid_by_username(&self, username: &str) -> Result<Option<u64>, AccountError<String>> {
        let conn = self.get_conn()?;

        let query: Option<AnyRow> = sqlx::query(self.format("SELECT cid FROM cnacs WHERE username = ? LIMIT 1").as_str()).bind(username).fetch_optional(conn).await?;
        if let Some(row) = query {
            Ok(Some(u64::from_str(&row.try_get::<String, _>("cid")?)?))
        } else {
            Ok(None)
        }
    }

    async fn delete_client_by_username(&self, username: &str) -> Result<(), AccountError<String>> {
        let conn = self.get_conn()?;

        let query: AnyQueryResult = sqlx::query(self.format("DELETE FROM cnacs WHERE username = ?").as_str()).bind(username).execute(conn).await?;
        if query.rows_affected() != 0 { Ok(()) } else { Err(AccountError::Generic("Client does not exist".into())) }
    }

    // We want to also update the CNACs involved
    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError<String>> {
        let conn = self.get_conn()?;
        let cid0 = cid0.to_string();
        let cid1 = cid1.to_string();

        let _query = sqlx::query(self.format("INSERT INTO peers (peer_cid, cid, username) VALUES (?, ?, (SELECT username FROM cnacs WHERE cid=?)),(?, ?, (SELECT username FROM cnacs WHERE cid=?))").as_str())
            .bind(cid0.as_str()).bind(cid1.as_str()).bind(cid0.as_str())
            .bind(cid1.as_str()).bind(cid0.as_str()).bind(cid1.as_str())
            .execute(conn).await?;

        Ok(())
    }

    // We must update the CNAC && the sql database
    async fn register_p2p_as_client(&self, implicated_cid: u64, peer_cid: u64, peer_username: String) -> Result<(), AccountError<String>> {
        let conn = self.get_conn()?;
        let _query = sqlx::query(self.format("INSERT INTO peers (peer_cid, cid, username) VALUES (?, ?, ?)").as_str()).bind(peer_cid.to_string()).bind(implicated_cid.to_string()).bind(peer_username).execute(conn).await?;
        Ok(())
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError<String>> {
        let conn = self.get_conn()?;
        let cid0 = cid0.to_string();
        let cid1 = cid1.to_string();

        let _query = sqlx::query(self.format("DELETE FROM peers WHERE (peer_cid = ? AND cid = ?) OR (peer_cid = ? AND cid = ?)").as_str()).bind(cid0.as_str()).bind(cid1.as_str()).bind(cid1.as_str()).bind(cid0.as_str()).execute(conn).await?;

        Ok(())
    }

    async fn deregister_p2p_as_client(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<MutualPeer>, AccountError<String>> {
        let conn = self.get_conn()?;
        let mut tx = conn.begin().await?;
        let row: AnyRow = sqlx::query(self.format("SELECT username FROM peers WHERE peer_cid = ? AND cid = ?").as_str()).bind(peer_cid.to_string()).bind(implicated_cid.to_string()).fetch_one(tx.deref_mut()).await?;
        let peer_username: String = row.try_get("username")?;
        let _query = sqlx::query(self.format("DELETE FROM peers WHERE peer_cid = ? AND cid = ?").as_str()).bind(peer_cid.to_string()).bind(implicated_cid.to_string()).execute(tx.deref_mut()).await?;
        tx.commit().await?;

        Ok(Some(MutualPeer { cid: peer_cid, parent_icid: HYPERLAN_IDX, username: Some(peer_username) }))
    }

    // In the server, we search the cnacs table
    async fn get_fcm_keys_for_as_server(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<FcmKeys>, AccountError<String>> {
        if self.hyperlan_peer_exists(implicated_cid, peer_cid).await? {
            let conn = self.get_conn()?;
            let query: AnyRow = sqlx::query(self.format("SELECT fcm_addr, fcm_api_key FROM cnacs WHERE cid = ? LIMIT 1").as_str()).bind(peer_cid.to_string()).fetch_one(conn).await?;

            Ok(self.maybe_get_fcm_keys(query))
        } else {
            Err(AccountError::Generic("Clients not mutually-registered".to_string()))
        }
    }

    async fn update_fcm_keys(&self, cnac: &ClientNetworkAccount<R, Fcm>, new_keys: FcmKeys) -> Result<(), AccountError<String>> {
        cnac.store_fcm_keys(new_keys);
        self.save_cnac(cnac.clone()).await
    }

    async fn get_hyperlan_peer_list(&self, implicated_cid: u64) -> Result<Option<Vec<u64>>, AccountError<String>> {
        let conn = self.get_conn()?;
        let query: Vec<AnyRow> = sqlx::query(self.format("SELECT peer_cid FROM peers WHERE cid = ?").as_str()).bind(implicated_cid.to_string()).fetch_all(conn).await?;
        let map = query.into_iter().filter_map(|row| row.try_get::<String, _>("peer_cid").ok()).filter_map(|val| u64::from_str(val.as_str()).ok()).collect::<Vec<u64>>();
        if map.is_empty() { Ok(None) } else { Ok(Some(map)) }
    }

    async fn get_client_metadata(&self, implicated_cid: u64) -> Result<Option<CNACMetadata>, AccountError<String>> {
        let conn = self.get_conn()?;
        // cnacs(cid VARCHAR(20) NOT NULL, is_connected BOOL, is_personal BOOL, fcm_addr TEXT, fcm_api_key TEXT, username VARCHAR({}) UNIQUE, full_name TEXT, creation_date TEXT, bin LONGTEXT, PRIMARY KEY (cid)
        let query: AnyRow = sqlx::query(self.format("SELECT is_personal, username, full_name, creation_date FROM cnacs WHERE cid = ? LIMIT 1").as_str()).bind(implicated_cid.to_string()).fetch_one(conn).await?;
        let is_personal = self.get_bool(&query, "is_personal")?;
        let username = query.try_get("username")?;
        let full_name = query.try_get("full_name")?;
        let creation_date = query.try_get("creation_date")?;
        Ok(Some(CNACMetadata { cid: implicated_cid, is_personal, username, full_name, creation_date }))
    }

    async fn get_clients_metadata(&self, limit: Option<i32>) -> Result<Vec<CNACMetadata>, AccountError<String>> {
        let conn = self.get_conn()?;
        // cnacs(cid VARCHAR(20) NOT NULL, is_connected BOOL, is_personal BOOL, fcm_addr TEXT, fcm_api_key TEXT, username VARCHAR({}) UNIQUE, full_name TEXT, creation_date TEXT, bin LONGTEXT, PRIMARY KEY (cid)
        let query = if let Some(limit) = limit {
             format!("SELECT cid, is_personal, username, full_name, creation_date FROM cnacs LIMIT {}", limit)
        } else {
            "SELECT cid, is_personal, username, full_name, creation_date FROM cnacs".to_string()
        };

        let query: Vec<AnyRow> = sqlx::query(query.as_str()).fetch_all(conn).await?;

        Ok(query.into_iter().filter_map(|query| {
            log::info!("A");
            let cid = query.try_get::<String, _>("cid").ok()?;
            log::info!("B");
            let cid = u64::from_str(cid.as_str()).ok()?;
            log::info!("C");
            let is_personal = self.get_bool(&query, "is_personal").ok()?;
            log::info!("D");
            let username = query.try_get("username").ok()?;
            log::info!("E");
            let full_name = query.try_get("full_name").ok()?;
            log::info!("F");
            let creation_date = query.try_get("creation_date").ok()?;
            log::info!("G");
            Some(CNACMetadata { cid, is_personal, username, full_name, creation_date })
        }).collect())
    }

    async fn get_hyperlan_peer_by_cid(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<MutualPeer>, AccountError<String>> {
        let conn = self.get_conn()?;
        let query: AnyRow = sqlx::query(self.format("SELECT username FROM peers WHERE cid = ? AND peer_cid = ? LIMIT 1").as_str()).bind(implicated_cid.to_string()).bind(peer_cid.to_string()).fetch_one(conn).await?;
        match query.try_get::<String, _>("username") {
            Ok(username) => {
                Ok(Some(MutualPeer { username: Some(username), parent_icid: HYPERLAN_IDX, cid: peer_cid }))
            }

            _ => {
                Ok(None)
            }
        }
    }

    async fn hyperlan_peer_exists(&self, implicated_cid: u64, peer_cid: u64) -> Result<bool, AccountError<String>> {
        let conn = self.get_conn()?;
        let query: AnyRow = sqlx::query(self.format("SELECT COUNT(*) as count FROM peers WHERE peer_cid = ? AND cid = ? LIMIT 1").as_str()).bind(peer_cid.to_string()).bind(implicated_cid.to_string()).fetch_one(conn).await?;

        Ok(query.try_get::<i64, _>("count").unwrap_or(-1) == 1)
    }

    async fn hyperlan_peers_are_mutuals(&self, implicated_cid: u64, peers: &Vec<u64>) -> Result<Vec<bool>, AccountError<String>> {
        if peers.is_empty() {
            return Ok(Vec::new())
        }

        let conn = self.get_conn()?;
        let limit = peers.len();

        let insert = self.construct_arg_insert_any(peers);

        let query = format!("WITH input(peer_cid) AS (VALUES {}) SELECT peers.peer_cid FROM input INNER JOIN peers ON input.peer_cid = peers.peer_cid WHERE peers.cid = ? LIMIT {}", insert, limit);

        let query: Vec<AnyRow> = sqlx::query(self.format(query).as_str()).bind(implicated_cid.to_string()).fetch_all(conn).await?;

        let results = query.into_iter().filter_map(|r| r.try_get::<String, _>("peer_cid").ok())
            .filter_map(|v| u64::from_str(v.as_str()).ok()).collect::<Vec<u64>>();

        Ok(peers.into_iter().map(|cid| results.iter().any(|peer_cid| *cid == *peer_cid)).collect())
    }

    async fn get_hyperlan_peers(&self, implicated_cid: u64, peers: &Vec<u64>) -> Result<Vec<MutualPeer>, AccountError<String>> {
        if peers.is_empty() {
            return Ok(Vec::new())
        }

        let conn = self.get_conn()?;
        let limit = peers.len();

        let insert = self.construct_arg_insert_any(peers);

        let query = format!("WITH input(peer_cid) AS (VALUES {}) SELECT peers.peer_cid, peers.username FROM input INNER JOIN peers ON input.peer_cid = peers.peer_cid WHERE peers.cid = ? LIMIT {}", insert, limit);

        let query: Vec<AnyRow> = sqlx::query(self.format(query).as_str()).bind(implicated_cid.to_string()).fetch_all(conn).await?;
        Ok(query.into_iter().filter_map(|row| {
            let peer_cid: String = row.try_get("peer_cid").ok()?;
            let peer_cid = u64::from_str(&peer_cid).ok()?;
            let peer_username: String = row.try_get("username").ok()?;
            Some(MutualPeer { parent_icid: HYPERLAN_IDX, cid: peer_cid, username: Some(peer_username) })
        }).collect())
    }

    async fn get_hyperlan_peers_with_fcm_keys(&self, implicated_cid: u64, peers: &Vec<u64>) -> Result<Vec<(MutualPeer, Option<FcmKeys>)>, AccountError<String>> {
        if peers.is_empty() {
            return Ok(Vec::new())
        }

        let conn = self.get_conn()?;
        let limit = peers.len();

        let insert = self.construct_arg_insert_any(peers);

        let query = format!("WITH input(peer_cid) AS (VALUES {}) SELECT peers.peer_cid, peers.username, cnacs.fcm_addr, cnacs.fcm_api_key FROM input INNER JOIN peers ON input.peer_cid = peers.peer_cid INNER JOIN cnacs ON input.peer_cid = cnacs.cid WHERE peers.cid = ? LIMIT {}", insert, limit);

        let query: Vec<AnyRow> = sqlx::query(self.format(query).as_str()).bind(implicated_cid.to_string()).fetch_all(conn).await?;
        Ok(query.into_iter().filter_map(|row| {
            let peer_cid: String = row.try_get("peer_cid").ok()?;
            let peer_cid = u64::from_str(&peer_cid).ok()?;
            let peer_username: String = row.try_get("username").ok()?;
            let keys = self.maybe_get_fcm_keys(row);
            Some((MutualPeer { parent_icid: HYPERLAN_IDX, cid: peer_cid, username: Some(peer_username) }, keys))
        }).collect())
    }

    async fn get_hyperlan_peer_by_username(&self, implicated_cid: u64, username: &str) -> Result<Option<MutualPeer>, AccountError<String>> {
        let conn = self.get_conn()?;
        let query: AnyRow = sqlx::query(self.format("SELECT peer_cid FROM peers WHERE cid = ? AND username = ? LIMIT 1").as_str()).bind(implicated_cid.to_string()).bind(username).fetch_one(conn).await?;
        match query.try_get::<String, _>("peer_cid") {
            Ok(username) => {
                let peer_cid = u64::from_str(username.as_str())?;
                Ok(Some(MutualPeer { username: Some(username.to_string()), parent_icid: HYPERLAN_IDX, cid: peer_cid }))
            }

            _ => {
                Ok(None)
            }
        }
    }

    // since server, we get the FCM keys from the cnacs table
    async fn get_hyperlan_peer_list_with_fcm_keys_as_server(&self, implicated_cid: u64) -> Result<Option<Vec<(u64, Option<String>, Option<FcmKeys>)>>, AccountError<String>> {
        let conn = self.get_conn()?;
        let query: Vec<AnyRow> = sqlx::query(self.format("SELECT peers.peer_cid, peers.username, cnacs.fcm_addr, cnacs.fcm_api_key FROM cnacs INNER JOIN peers ON cnacs.cid = peers.cid WHERE peers.cid = ?").as_str()).bind(implicated_cid.to_string()).fetch_all(conn).await?;
        let mut ret = Vec::with_capacity(query.len());

        for row in query {
            let peer_cid = row.try_get::<String, _>("peer_cid")?;
            let peer_cid = u64::from_str(peer_cid.as_str())?;
            let username = row.try_get::<String, _>("username")?;
            let keys = self.maybe_get_fcm_keys(row);
            ret.push((peer_cid, Some(username), keys))
        }

        if ret.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ret))
        }
    }

    // We always return false here, since there's no need for manual saving
    async fn synchronize_hyperlan_peer_list_as_client(&self, cnac: &ClientNetworkAccount<R, Fcm>, peers: Vec<(u64, Option<String>, Option<FcmKeys>)>) -> Result<bool, AccountError<String>> {
        if peers.len() != 0 {
            let conn = self.get_conn()?;
            let mut tx = conn.begin().await?;
            let implicated_cid = cnac.get_cid().to_string();

            let _ = sqlx::query(self.format("DELETE FROM peers WHERE cid = ?").as_str()).bind(implicated_cid.as_str()).execute(tx.deref_mut()).await?;
            for (peer_cid, username, fcm_keys) in peers {
                // TODO: Optimize this
                cnac.store_fcm_keys_for_peer(peer_cid, fcm_keys);
                let _ = sqlx::query(self.format("INSERT INTO peers (peer_cid, username, cid) VALUES(?, ?, ?)").as_str()).bind(peer_cid.to_string()).bind(username.unwrap_or_else(|| "NULL".into())).bind(implicated_cid.as_str()).execute(tx.deref_mut()).await?;
            }

            tx.commit().await?;
            self.save_cnac(cnac.clone()).await?;
        }

        Ok(false)
    }

    fn store_cnac(&self, _cnac: ClientNetworkAccount<R, Fcm>) {}

    fn uses_remote_db(&self) -> bool {
        true
    }

    fn get_local_map(&self) -> Option<Arc<ShardedLock<HashMap<u64, ClientNetworkAccount<R, Fcm>, RandomState>>>> {
        None
    }

    fn local_nac(&self) -> &NetworkAccount<R, Fcm> {
        self.local_nac.as_ref().unwrap()
    }
}

impl<R: Ratchet, Fcm: Ratchet> SqlBackend<R, Fcm> {
    fn get_conn(&self) -> Result<&AnyPool, AccountError> {
        self.conn.as_ref().ok_or(AccountError::Generic("Connection not loaded".to_string()))
    }

    fn row_to_cnac(&self, query: Option<AnyRow>, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        if let Some(row) = query {
            let bin: String = row.try_get("bin")?;
            let bin = base64::decode(bin)?;
            let cnac_inner = ClientNetworkAccountInner::<R, Fcm>::deserialize_from_vector(&bin[..])?;
            Ok(Some(ClientNetworkAccount::load_safe(cnac_inner, None, Some(persistence_handler.clone()))?))
        } else {
            Ok(None)
        }
    }

    fn construct_arg_insert_any(&self, vals: &Vec<u64>) -> String {
        match self.variant {
            SqlVariant::MySQL => {
                self.construct_arg_insert_mysql(vals)
            }

            SqlVariant::Sqlite => {
                self.construct_arg_insert_sqlite(vals)
            }

            SqlVariant::Postgre => {
                self.construct_arg_insert_postgre(vals)
            }
        }
    }

    fn construct_arg_insert_mysql(&self, vals: &Vec<u64>) -> String {
        let mut ret = String::new();
        let len = vals.len();

        for idx in 0..len-1 {
            ret += &format!("ROW('{}'),", vals[idx]);
        }

        ret += &format!("ROW('{}')", vals[len-1]);
        ret
    }

    fn construct_arg_insert_postgre(&self, vals: &Vec<u64>) -> String {
        let mut ret = String::new();
        let len = vals.len();

        for idx in 0..len-1 {
            ret += &format!("('{}'),", vals[idx]);
        }

        ret += &format!("('{}')", vals[len-1]);
        ret
    }

    fn construct_arg_insert_sqlite(&self, vals: &Vec<u64>) -> String {
        self.construct_arg_insert_postgre(vals)
    }

    fn maybe_get_fcm_keys(&self, row: AnyRow) -> Option<FcmKeys> {
        if let Ok(fcm_addr) = row.try_get::<String, _>("fcm_addr") {
            if let Ok(fcm_api_key) = row.try_get::<String, _>("fcm_api_key") {
                return if fcm_addr == "NULL" || fcm_api_key == "NULL" {
                    None
                } else {
                    Some(FcmKeys::new(fcm_api_key, fcm_addr))
                }
            }
        }

        None
    }

    fn format<T: Into<String>>(&self, input: T) -> String {
        match self.variant {
            SqlVariant::MySQL | SqlVariant::Sqlite => {
                input.into()
            }

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

impl<R: Ratchet, Fcm:Ratchet, T: Into<String>> TryFrom<(T, BackendType)> for SqlBackend<R, Fcm> {
    type Error = ();

    fn try_from(t: (T, BackendType)) -> Result<Self, ()> {
        Ok(Self { url: t.0.into(), conn: None, local_nac: None, variant: t.1.try_into()? })
    }
}

impl TryFrom<BackendType> for SqlVariant {
    type Error = ();

    fn try_from(this: BackendType) -> Result<Self, ()> {
        match this {
            BackendType::SQLDatabase(url) => {
                if url.starts_with("mysql") {
                    return Ok(SqlVariant::MySQL)
                }

                if url.starts_with("postgre") {
                    return Ok(SqlVariant::Postgre)
                }

                if url.starts_with("sqlite") {
                    return Ok(SqlVariant::Sqlite)
                }
            }
            _ => {}
        }

        Err(())
    }
}