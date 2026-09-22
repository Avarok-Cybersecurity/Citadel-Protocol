//! Byte-map rows: one per `(cid, peer_cid, key, sub_key)`, unique, so a store overwrites the
//! entry it names (#305) and a write costs the size of that one entry, not of the account.

use super::{cid_value, read_blob, read_text, schema, text_value, HostSqlBackend, SqlStatement};
use crate::misc::AccountError;
use citadel_crypt::ratchets::Ratchet;
use std::collections::HashMap;

impl<R: Ratchet, Fcm: Ratchet> HostSqlBackend<R, Fcm> {
    pub(super) async fn entry(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let rows = self
            .query(
                schema::SELECT_BYTEMAP,
                entry_key(session_cid, peer_cid, key, sub_key),
            )
            .await?;
        previous(rows)
    }

    /// Stores `value` and returns the value it replaced, read in the same transaction.
    pub(super) async fn store_entry(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let entry = entry_key(session_cid, peer_cid, key, sub_key);
        let mut upsert = entry.clone();
        upsert.push(super::SqlValue::Blob(value));
        let mut results = self
            .run(vec![
                SqlStatement {
                    sql: schema::SELECT_BYTEMAP,
                    params: entry,
                },
                SqlStatement {
                    sql: schema::UPSERT_BYTEMAP,
                    params: upsert,
                },
            ])
            .await?;
        previous(results.swap_remove(0))
    }

    /// Removes the entry and returns what it held, read in the same transaction.
    pub(super) async fn remove_entry(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
        sub_key: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let entry = entry_key(session_cid, peer_cid, key, sub_key);
        let mut results = self
            .run(vec![
                SqlStatement {
                    sql: schema::SELECT_BYTEMAP,
                    params: entry.clone(),
                },
                SqlStatement {
                    sql: schema::DELETE_BYTEMAP,
                    params: entry,
                },
            ])
            .await?;
        previous(results.swap_remove(0))
    }

    pub(super) async fn entries(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let rows = self
            .query(
                schema::SELECT_BYTEMAP_BY_KEY,
                map_key(session_cid, peer_cid, key),
            )
            .await?;
        to_map(rows)
    }

    /// Removes every entry under `key` and returns them, read in the same transaction.
    pub(super) async fn remove_entries(
        &self,
        session_cid: u64,
        peer_cid: u64,
        key: &str,
    ) -> Result<HashMap<String, Vec<u8>>, AccountError> {
        let params = map_key(session_cid, peer_cid, key);
        let mut results = self
            .run(vec![
                SqlStatement {
                    sql: schema::SELECT_BYTEMAP_BY_KEY,
                    params: params.clone(),
                },
                SqlStatement {
                    sql: schema::DELETE_BYTEMAP_BY_KEY,
                    params,
                },
            ])
            .await?;
        to_map(results.swap_remove(0))
    }
}

fn map_key(session_cid: u64, peer_cid: u64, key: &str) -> Vec<super::SqlValue> {
    vec![cid_value(session_cid), cid_value(peer_cid), text_value(key)]
}

fn entry_key(session_cid: u64, peer_cid: u64, key: &str, sub_key: &str) -> Vec<super::SqlValue> {
    let mut params = map_key(session_cid, peer_cid, key);
    params.push(text_value(sub_key));
    params
}

fn previous(rows: Vec<super::SqlRow>) -> Result<Option<Vec<u8>>, AccountError> {
    rows.into_iter()
        .next()
        .map(|row| read_blob(row, 0))
        .transpose()
}

fn to_map(rows: Vec<super::SqlRow>) -> Result<HashMap<String, Vec<u8>>, AccountError> {
    rows.into_iter()
        .map(|row| {
            let sub_key = read_text(&row, 0)?;
            Ok((sub_key, read_blob(row, 1)?))
        })
        .collect()
}
