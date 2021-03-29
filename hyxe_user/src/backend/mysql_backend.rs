use async_trait::async_trait;
use crate::backend::{BackendConnection, PersistenceHandler, BackendType};
use crate::misc::{AccountError, MAX_USERNAME_LENGTH};
use sqlx::{Connection, AnyConnection, Arguments, Row};
use tokio::sync::Mutex;
use hyxe_crypt::hyper_ratchet::{Ratchet, HyperRatchet};
use crate::client_account::ClientNetworkAccount;
use std::ops::DerefMut;
use sqlx::any::{AnyArguments, AnyRow, AnyQueryResult};
use crate::prelude::{ClientNetworkAccountInner, NetworkAccount};
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

/// A container for handling db conns
pub struct SqlBackend<R: Ratchet = HyperRatchet, Fcm: Ratchet = FcmRatchet> {
    url: String,
    conn: Option<Mutex<AnyConnection>>,
    local_nac: Option<NetworkAccount<R, Fcm>>,
    variant: SqlVariant
}

enum SqlVariant {
    MySQL,
    #[allow(dead_code)]
    Postgre
}

#[async_trait]
impl<R: Ratchet, Fcm: Ratchet> BackendConnection<R, Fcm> for SqlBackend<R, Fcm> {
    // NOTE: Multiple backends should be created, one for each CNAC connected. We don't want just one query executing at a time, that is bad?
    async fn connect(&mut self, directory_store: &DirectoryStore) -> Result<(), AccountError<String>> {
        let mut conn = sqlx::any::AnyConnection::connect(&self.url).await.map_err(|err| AccountError::Generic(format!("{:?}", err)))?;

        // we use varchar(20) for a u64 since u64::MAX char count = 20

        // The below works on MySql, Postgre, SqLite,
        let cmd = format!("CREATE TABLE IF NOT EXISTS cnacs(cid VARCHAR(20) NOT NULL, isConnected BOOL, isPersonal BOOL, fcmAddr TEXT, fcmApiKey TEXT, username VARCHAR({}) UNIQUE, bin LONGTEXT, PRIMARY KEY (cid))", MAX_USERNAME_LENGTH);
        let cmd2 = format!("CREATE TABLE IF NOT EXISTS peers(peerCid VARCHAR(20), username TEXT, cid VARCHAR(20), CONSTRAINT fk_cid FOREIGN KEY (cid) REFERENCES cnacs(cid) ON DELETE CASCADE)");

        {
            let _query0 = sqlx::query(&cmd).execute(&mut conn).await?;
            let _query1 =  sqlx::query(&cmd2).execute(&mut conn).await?;
        }



        self.conn =  Some(Mutex::new(conn));
        self.local_nac = Some(load_node_nac(true, directory_store)?);

        Ok(())
    }

    fn post_connect(&self, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<(), AccountError<String>> {
        // we just need to insert the persistence handler inside the nac
        self.local_nac().store_persistence_handler(persistence_handler);
        Ok(())
    }

    async fn is_connected(&self) -> Result<bool, AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        Ok(conn.ping().await.is_ok())
    }

    async fn save_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        let serded = base64::encode(cnac.generate_proper_bytes()?);
        let mut args = AnyArguments::default();
        let keys = cnac.get_fcm_keys();

        let fcm_api_key = keys.as_ref().map(|f| f.api_key.clone());
        let fcm_addr = keys.as_ref().map(|f| f.client_id.clone());

        args.add(cnac.get_cid().to_string());
        args.add(true);
        args.add(cnac.is_personal());
        args.add(fcm_addr.unwrap_or_else(||"NULL".into()));
        args.add(fcm_api_key.unwrap_or_else(|| "NULL".into()));
        args.add(cnac.get_username());
        args.add(serded);

        let _query = sqlx::query_with("REPLACE INTO cnacs VALUES(?, ?, ?, ?, ?, ?, ?)", args).execute(conn.deref_mut()).await.map_err(|err| AccountError::Generic(format!("{:?}",err)))?;

        Ok(())
    }

    async fn get_cnac_by_cid(&self, cid: u64, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        let query: Option<AnyRow> = sqlx::query("SELECT bin FROM cnacs WHERE cid = ? LIMIT 1").bind(cid.to_string()).fetch_optional(conn.deref_mut()).await?;
        self.row_to_cnac(query, persistence_handler)
    }

    async fn get_client_by_username(&self, username: &str, persistence_handler: &PersistenceHandler<R, Fcm>) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        let query: Option<AnyRow> = sqlx::query("SELECT bin FROM cnacs WHERE username = ? LIMIT 1").bind(username).fetch_optional(conn.deref_mut()).await?;
        self.row_to_cnac(query, persistence_handler)
    }

    async fn cid_is_registered(&self, cid: u64) -> Result<bool, AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        let query = sqlx::query("SELECT cid FROM cnacs WHERE cid = ? LIMIT 1").bind(cid.to_string()).fetch_all(conn.deref_mut()).await?;
        Ok(query.len() == 1)
    }

    async fn delete_cnac(&self, cnac: ClientNetworkAccount<R, Fcm>) -> Result<(), AccountError<String>> {
        self.delete_cnac_by_cid(cnac.get_cid()).await
    }

    async fn delete_cnac_by_cid(&self, cid: u64) -> Result<(), AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        let query: AnyQueryResult = sqlx::query("DELETE FROM cnacs WHERE cid = ? LIMIT 1").bind(cid.to_string()).execute(conn.deref_mut()).await?;
        if query.rows_affected() != 0 { Ok(()) } else { Err(AccountError::ClientNonExists(cid)) }
    }

    async fn save_all(&self) -> Result<(), AccountError<String>> {
        self.local_nac().save_to_local_fs()?;
        // we don't have to save any cnacs, since those are already saved on the database
        Ok(())
    }

    async fn purge(&self) -> Result<usize, AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        let query: AnyQueryResult = sqlx::query("DELETE FROM cnacs").execute(conn.deref_mut()).await?;
        Ok(query.rows_affected() as usize)
    }

    async fn client_count(&self) -> Result<usize, AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        let query: AnyRow = sqlx::query("SELECT COUNT(*) as count FROM cnacs").fetch_one(conn.deref_mut()).await?;
        Ok(query.get::<i64, _>("count") as usize)
    }

    fn maybe_generate_cnac_local_save_path(&self, _cid: u64, _is_personal: bool) -> Option<PathBuf> {
        None
    }

    async fn find_first_valid_cid(&self, possible_cids: &Vec<u64>) -> Result<Option<u64>, AccountError> {
        let mut conn = self.get_conn()?.lock().await;

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
        };

        let query: AnyRow = sqlx::query(cmd.as_str()).fetch_one(conn.deref_mut()).await?;

        if let Ok(val) = query.try_get::<String, _>("cid") {
            let available_cid = u64::from_str(&val)?;
            Ok(Some(available_cid))
        } else {
            Ok(None)
        }
    }

    async fn username_exists(&self, username: &str) -> Result<bool, AccountError> {
        let mut conn = self.get_conn()?.lock().await;
        let query: AnyRow = sqlx::query("SELECT COUNT(1) as count FROM cnacs where username = ?").bind(username).fetch_one(conn.deref_mut()).await?;
        Ok(query.get::<i64, _>("count") == 1)
    }

    async fn register_cid(&self, _cid: u64, _username: &str) -> Result<(), AccountError<String>> {
        // we don't register here since we don't need to store inside the local nac
        Ok(())
    }

    async fn get_registered_impersonal_cids(&self, limit: Option<i32>) -> Result<Option<Vec<u64>>, AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        let cmd = limit.map(|limit| format!("SELECT cid FROM cnacs WHERE isPersonal = ? LIMIT {}", limit)).unwrap_or_else(|| "SELECT cid FROM cnacs WHERE isPersonal = ?".to_string());
        let query: Vec<AnyRow> = sqlx::query(&cmd).bind(false).fetch_all(conn.deref_mut()).await?;
        let ret: Vec<u64> = query.into_iter().filter_map(|r| r.try_get::<String,_>("cid").ok()).filter_map(|r| u64::from_str(&r).ok()).collect();

        if ret.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ret))
        }
    }

    async fn get_username_by_cid(&self, cid: u64) -> Result<Option<String>, AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        let query: Option<AnyRow> = sqlx::query("SELECT username FROM cnacs WHERE cid = ? LIMIT 1").bind(cid.to_string()).fetch_optional(conn.deref_mut()).await?;
        if let Some(row) = query {
            Ok(Some(row.try_get::<String, _>("username").unwrap()))
        } else {
            Ok(None)
        }
    }

    async fn get_cid_by_username(&self, username: &str) -> Result<Option<u64>, AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;

        let query: Option<AnyRow> = sqlx::query("SELECT cid FROM cnacs WHERE username = ? LIMIT 1").bind(username).fetch_optional(conn.deref_mut()).await?;
        if let Some(row) = query {
            Ok(Some(u64::from_str(&row.try_get::<String, _>("cid")?)?))
        } else {
            Ok(None)
        }
    }

    async fn delete_client_by_username(&self, username: &str) -> Result<(), AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;

        let query: AnyQueryResult = sqlx::query("DELETE FROM cnacs WHERE username = ? LIMIT 1").bind(username).execute(conn.deref_mut()).await?;
        if query.rows_affected() != 0 { Ok(()) } else { Err(AccountError::Generic("Client does not exist".into())) }
    }

    async fn register_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        // TODO: Optimize below into a single query
        let _query = sqlx::query("REPLACE INTO peers (peerCid, cid) VALUES (?, ?)").bind(cid0.to_string()).bind(cid1.to_string()).execute(conn.deref_mut()).await?;
        let _query = sqlx::query("REPLACE INTO peers (peerCid, cid) VALUES (?, ?)").bind(cid1.to_string()).bind(cid0.to_string()).execute(conn.deref_mut()).await?;

        Ok(())
    }

    async fn deregister_p2p_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        // TODO: Optimize below into a single query
        let _query = sqlx::query("DELETE FROM peers WHERE peerCid = ? AND cid = ? LIMIT 1").bind(cid0.to_string()).bind(cid1.to_string()).execute(conn.deref_mut()).await?;
        let _query = sqlx::query("DELETE FROM peers WHERE peerCid = ? AND cid = ? LIMIT 1").bind(cid1.to_string()).bind(cid0.to_string()).execute(conn.deref_mut()).await?;

        Ok(())
    }

    async fn get_fcm_keys_for(&self, implicated_cid: u64, peer_cid: u64) -> Result<Option<FcmKeys>, AccountError<String>> {
        if self.is_registered_to(implicated_cid, peer_cid).await? {
            let mut conn = self.get_conn()?.lock().await;
            let query: AnyRow = sqlx::query("SELECT (fcmAddr, fcmApiKey) FROM cnacs WHERE cid = ? LIMIT 1").bind(peer_cid.to_string()).fetch_one(conn.deref_mut()).await?;

            if let Ok(fcm_addr) = query.try_get::<String, _>("fcmAddr") {
                if let Ok(fcm_api_key) = query.try_get::<String, _>("fcmApiKey") {
                    return if fcm_addr == "NULL" || fcm_api_key == "NULL" {
                        Ok(None)
                    } else {
                        Ok(Some(FcmKeys::new(fcm_api_key, fcm_addr)))
                    }
                }
            }

            Ok(None)
        } else {
            Err(AccountError::Generic("Clients not mutually-registered".to_string()))
        }
    }

    async fn is_registered_to(&self, implicated_cid: u64, peer_cid: u64) -> Result<bool, AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        let query: AnyRow = sqlx::query("SELECT COUNT(*) as count FROM peers WHERE peerCid = ? AND cid = ? LIMIT 1").bind(peer_cid.to_string()).bind(implicated_cid.to_string()).fetch_one(conn.deref_mut()).await?;

        Ok(query.try_get::<i64, _>("count").unwrap_or(-1) == 1)
    }

    async fn get_hyperlan_peer_list(&self, implicated_cid: u64) -> Result<Option<Vec<u64>>, AccountError<String>> {
        let mut conn = self.get_conn()?.lock().await;
        let query: Vec<AnyRow> = sqlx::query("SELECT (peerCid) FROM peers WHERE cid = ?").bind(implicated_cid.to_string()).fetch_all(conn.deref_mut()).await?;
        let map = query.into_iter().filter_map(|row| row.try_get::<String, _>("peerCid").ok()).filter_map(|val| u64::from_str(val.as_str()).ok()).collect::<Vec<u64>>();
        if map.is_empty() { Ok(None) } else { Ok(Some(map)) }
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
    fn get_conn(&self) -> Result<&Mutex<AnyConnection>, AccountError> {
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
}

impl<R: Ratchet, Fcm:Ratchet, T: Into<String>> From<(T, BackendType)> for SqlBackend<R, Fcm> {
    fn from(t: (T, BackendType)) -> Self {
        Self { url: t.0.into(), conn: None, local_nac: None, variant: t.1.into() }
    }
}

impl From<BackendType> for SqlVariant {
    fn from(this: BackendType) -> Self {
        match this {
            BackendType::MySQLDatabase(_) => SqlVariant::MySQL,
            _ => unreachable!()
        }
    }
}