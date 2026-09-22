//! Account rows: one per CNAC, holding its serialized form and the metadata queried on its own.

use super::{
    cid_value, read_blob, read_cid, read_integer, read_text, schema, text_value, HostSqlBackend,
    SqlRow, SqlStatement, SqlValue,
};
use crate::client_account::ClientNetworkAccount;
use crate::misc::{AccountError, CNACMetadata};
use crate::serialization::SyncIO;
use citadel_crypt::ratchets::Ratchet;

impl<R: Ratchet, Fcm: Ratchet> HostSqlBackend<R, Fcm> {
    pub(super) async fn save_account(
        &self,
        cnac: &ClientNetworkAccount<R, Fcm>,
    ) -> Result<(), AccountError> {
        let bin = cnac.generate_proper_bytes()?;
        let meta = cnac.get_metadata();
        let params = vec![
            cid_value(meta.cid),
            SqlValue::Integer(meta.is_personal as i64),
            text_value(meta.username),
            text_value(meta.full_name),
            text_value(meta.creation_date),
            SqlValue::Blob(bin),
        ];
        self.query(schema::UPSERT_CNAC, params).await.map(|_| ())
    }

    pub(super) async fn load_account(
        &self,
        cid: u64,
    ) -> Result<Option<ClientNetworkAccount<R, Fcm>>, AccountError> {
        let row = self
            .query(schema::SELECT_CNAC_BIN, vec![cid_value(cid)])
            .await?
            .into_iter()
            .next();
        match row {
            Some(row) => {
                let bin = read_blob(row, 0)?;
                Ok(Some(
                    ClientNetworkAccount::<R, Fcm>::deserialize_from_owned_vector(bin)?,
                ))
            }
            None => Ok(None),
        }
    }

    pub(super) async fn account_exists(&self, cid: u64) -> Result<bool, AccountError> {
        let rows = self
            .query(schema::SELECT_CNAC_EXISTS, vec![cid_value(cid)])
            .await?;
        Ok(!rows.is_empty())
    }

    /// The account, every pair it is part of (either side) and its byte map, in one transaction.
    pub(super) async fn delete_account(&self, cid: u64) -> Result<(), AccountError> {
        let statement = |sql, params| SqlStatement { sql, params };
        let results = self
            .run(vec![
                statement(schema::SELECT_CNAC_EXISTS, vec![cid_value(cid)]),
                statement(schema::DELETE_CNAC, vec![cid_value(cid)]),
                statement(
                    schema::DELETE_PEERS_OF_CNAC,
                    vec![cid_value(cid), cid_value(cid)],
                ),
                statement(schema::DELETE_BYTEMAP_OF_CNAC, vec![cid_value(cid)]),
            ])
            .await?;
        if results[0].is_empty() {
            return Err(AccountError::account_client_non_exists(cid));
        }
        Ok(())
    }

    pub(super) async fn purge_all(&self) -> Result<usize, AccountError> {
        let statement = |sql| SqlStatement {
            sql,
            params: Vec::new(),
        };
        let results = self
            .run(vec![
                statement(schema::COUNT_CNACS),
                statement(schema::DELETE_ALL_PEERS),
                statement(schema::DELETE_ALL_BYTEMAP),
                statement(schema::DELETE_ALL_CNACS),
            ])
            .await?;
        let count = results[0]
            .first()
            .map(|row| read_integer(row, 0))
            .transpose()?
            .unwrap_or(0);
        usize::try_from(count).map_err(|_| super::op_error(format!("negative count {count}")))
    }

    pub(super) async fn impersonal_cids(
        &self,
        limit: Option<i32>,
    ) -> Result<Option<Vec<u64>>, AccountError> {
        let rows = self
            .query(schema::SELECT_IMPERSONAL_CIDS, vec![limit_value(limit)])
            .await?;
        let cids = rows
            .iter()
            .map(|row| read_cid(row, 0))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(if cids.is_empty() { None } else { Some(cids) })
    }

    pub(super) async fn account_text(
        &self,
        sql: &'static str,
        cid: u64,
    ) -> Result<Option<String>, AccountError> {
        let rows = self.query(sql, vec![cid_value(cid)]).await?;
        rows.first().map(|row| read_text(row, 0)).transpose()
    }

    pub(super) async fn metadata(&self, cid: u64) -> Result<Option<CNACMetadata>, AccountError> {
        let rows = self
            .query(schema::SELECT_METADATA, vec![cid_value(cid)])
            .await?;
        rows.first().map(row_to_metadata).transpose()
    }

    pub(super) async fn all_metadata(
        &self,
        limit: Option<i32>,
    ) -> Result<Vec<CNACMetadata>, AccountError> {
        let rows = self
            .query(schema::SELECT_CLIENTS_METADATA, vec![limit_value(limit)])
            .await?;
        rows.iter().map(row_to_metadata).collect()
    }
}

/// `-1` is SQLite's "no limit".
fn limit_value(limit: Option<i32>) -> SqlValue {
    SqlValue::Integer(limit.map(i64::from).unwrap_or(-1))
}

fn row_to_metadata(row: &SqlRow) -> Result<CNACMetadata, AccountError> {
    Ok(CNACMetadata {
        cid: read_cid(row, 0)?,
        is_personal: read_integer(row, 1)? != 0,
        username: read_text(row, 2)?,
        full_name: read_text(row, 3)?,
        creation_date: read_text(row, 4)?,
    })
}
