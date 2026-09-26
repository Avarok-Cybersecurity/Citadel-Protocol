//! A native [`SqlHost`]: an in-memory SQLite database, the same engine a Durable Object's
//! `ctx.storage.sql` runs, so the backend's statements are exercised as the host will run them.

use async_trait::async_trait;
use citadel_user::backend::host_sql::{
    HostSqlHandle, SqlHost, SqlRow, SqlStatement, SqlValue, StorageQuota,
};
use rusqlite::types::{Value, ValueRef};
use std::sync::Mutex;

pub struct SqliteHost {
    conn: Mutex<rusqlite::Connection>,
    quota: StorageQuota,
}

impl SqliteHost {
    pub fn in_memory(quota: StorageQuota) -> Self {
        Self {
            conn: Mutex::new(
                rusqlite::Connection::open_in_memory().expect("open in-memory sqlite"),
            ),
            quota,
        }
    }

    /// Unlimited: the suites using this handle test accounts, pairs and byte maps, which no
    /// storage quota governs; the RE-VFS tests choose their quota with `in_memory`.
    pub fn handle() -> HostSqlHandle {
        HostSqlHandle::new(Self::in_memory(StorageQuota::Unlimited))
    }
}

fn bind(value: &SqlValue) -> Value {
    match value {
        SqlValue::Null => Value::Null,
        SqlValue::Integer(n) => Value::Integer(*n),
        SqlValue::Text(s) => Value::Text(s.clone()),
        SqlValue::Blob(b) => Value::Blob(b.clone()),
    }
}

fn read(value: ValueRef<'_>) -> Result<SqlValue, String> {
    Ok(match value {
        ValueRef::Null => SqlValue::Null,
        ValueRef::Integer(n) => SqlValue::Integer(n),
        ValueRef::Text(t) => {
            SqlValue::Text(String::from_utf8(t.to_vec()).map_err(|e| e.to_string())?)
        }
        ValueRef::Blob(b) => SqlValue::Blob(b.to_vec()),
        ValueRef::Real(r) => return Err(format!("unexpected REAL {r}")),
    })
}

fn run_one(
    tx: &rusqlite::Transaction<'_>,
    statement: &SqlStatement,
) -> Result<Vec<SqlRow>, String> {
    let mut stmt = tx.prepare(statement.sql).map_err(|e| e.to_string())?;
    let columns = stmt.column_count();
    let params = rusqlite::params_from_iter(statement.params.iter().map(bind));
    let mut rows = stmt.query(params).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        out.push(
            (0..columns)
                .map(|i| read(row.get_ref(i).map_err(|e| e.to_string())?))
                .collect::<Result<SqlRow, String>>()?,
        );
    }
    Ok(out)
}

#[async_trait]
impl SqlHost for SqliteHost {
    async fn execute(&self, statements: Vec<SqlStatement>) -> Result<Vec<Vec<SqlRow>>, String> {
        let mut conn = self.conn.lock().map_err(|e| e.to_string())?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let results = statements
            .iter()
            .map(|statement| run_one(&tx, statement))
            .collect::<Result<Vec<_>, String>>()?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(results)
    }

    fn storage_quota(&self) -> Result<StorageQuota, String> {
        Ok(self.quota)
    }
}
