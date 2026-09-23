//! A backend over SQL storage the host process provides.
//!
//! The node does not open the database itself: the host hands it a [`SqlHost`], a single
//! method that runs a batch of SQLite statements atomically. That is the whole contract, so a
//! JS runtime (a Workers Durable Object's `ctx.storage.sql`, run inside `transactionSync`)
//! and a native in-process SQLite satisfy it alike, and the backend above it is the same code
//! in both — the one that the backend test suite runs natively.
//!
//! One row per account, per peer pair and per byte-map entry, so no single write grows with
//! the number of accounts or entries. Keys are unique by schema (see [`schema`]): a byte-map
//! store is an upsert, a pair recorded twice is one pair, and one removal removes it.

mod accounts;
mod backend;
mod bytemap;
mod peers;
mod schema;

pub use backend::HostSqlBackend;

use crate::misc::AccountError;
use async_trait::async_trait;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

/// A value bound into, or read out of, a statement. Integers must stay within ±2^53 so a JS
/// host can carry them as numbers; CIDs, which do not, travel as decimal text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SqlValue {
    /// SQL NULL
    Null,
    /// A 64-bit integer column value
    Integer(i64),
    /// A UTF-8 text column value
    Text(String),
    /// A binary column value
    Blob(Vec<u8>),
}

/// One statement and its positional (`?`) parameters.
#[derive(Clone, Debug)]
pub struct SqlStatement {
    /// SQLite statement text with `?` placeholders
    pub sql: &'static str,
    /// The values bound to the placeholders, in order
    pub params: Vec<SqlValue>,
}

/// A result row, columns in the order the statement selected them.
pub type SqlRow = Vec<SqlValue>;

/// SQL storage supplied by the host.
#[async_trait]
pub trait SqlHost: Send + Sync + 'static {
    /// Runs `statements` in order as one transaction: either every one applies or none does.
    /// Returns each statement's rows, in the same order. An `Err` carries the host's reason.
    async fn execute(&self, statements: Vec<SqlStatement>) -> Result<Vec<Vec<SqlRow>>, String>;
}

/// The [`SqlHost`] a [`crate::backend::BackendType::HostSql`] carries. Two handles are equal
/// only when they are the same host, which is what "the same backend" means for them.
#[derive(Clone)]
pub struct HostSqlHandle(pub Arc<dyn SqlHost>);

impl HostSqlHandle {
    /// Wraps a host's storage for use as a backend.
    pub fn new<T: SqlHost>(host: T) -> Self {
        Self(Arc::new(host))
    }
}

impl Debug for HostSqlHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HostSqlHandle({:p})", Arc::as_ptr(&self.0))
    }
}

impl PartialEq for HostSqlHandle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for HostSqlHandle {}

fn op_error(reason: impl Into<String>) -> AccountError {
    citadel_io::error!(citadel_io::ErrorCode::SqlOp, reason.into())
}

fn cid_value(cid: u64) -> SqlValue {
    SqlValue::Text(cid.to_string())
}

fn text_value(value: impl Into<String>) -> SqlValue {
    SqlValue::Text(value.into())
}

fn column(row: &SqlRow, idx: usize) -> Result<&SqlValue, AccountError> {
    row.get(idx)
        .ok_or_else(|| op_error(format!("row has no column {idx}")))
}

fn read_cid(row: &SqlRow, idx: usize) -> Result<u64, AccountError> {
    match column(row, idx)? {
        SqlValue::Text(text) => text
            .parse()
            .map_err(|_| citadel_io::error!(citadel_io::ErrorCode::SqlDecodePeerCid)),
        other => Err(unexpected(other)),
    }
}

fn read_text(row: &SqlRow, idx: usize) -> Result<String, AccountError> {
    match column(row, idx)? {
        SqlValue::Text(text) => Ok(text.clone()),
        other => Err(unexpected(other)),
    }
}

fn read_opt_text(row: &SqlRow, idx: usize) -> Result<Option<String>, AccountError> {
    match column(row, idx)? {
        SqlValue::Null => Ok(None),
        _ => read_text(row, idx).map(Some),
    }
}

fn read_blob(row: SqlRow, idx: usize) -> Result<Vec<u8>, AccountError> {
    match row.into_iter().nth(idx) {
        Some(SqlValue::Blob(bytes)) => Ok(bytes),
        Some(other) => Err(unexpected(&other)),
        None => Err(op_error(format!("row has no column {idx}"))),
    }
}

fn read_integer(row: &SqlRow, idx: usize) -> Result<i64, AccountError> {
    match column(row, idx)? {
        SqlValue::Integer(n) => Ok(*n),
        other => Err(unexpected(other)),
    }
}

fn unexpected(value: &SqlValue) -> AccountError {
    let kind = match value {
        SqlValue::Null => "null",
        SqlValue::Integer(_) => "integer",
        SqlValue::Text(_) => "text",
        SqlValue::Blob(_) => "blob",
    };
    citadel_io::error!(citadel_io::ErrorCode::SqlUnexpectedColumnType, kind)
}
