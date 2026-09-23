//! The tables, and every statement the backend runs against them (SQLite dialect).
//!
//! CIDs are decimal TEXT: they span the whole u64 range, which neither SQLite's signed
//! INTEGER nor a JS number can hold. The primary keys are what give the backend its
//! semantics — the SQL backend lacked them and so grew duplicate rows (#305, #306, #307).
//! Table names carry a `citadel_` prefix so a host can keep tables of its own beside them.

pub(super) const CREATE_TABLES: [&str; 3] = [
    "CREATE TABLE IF NOT EXISTS citadel_cnacs (cid TEXT NOT NULL PRIMARY KEY, is_personal INTEGER NOT NULL, username TEXT NOT NULL, full_name TEXT NOT NULL, creation_date TEXT NOT NULL, bin BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS citadel_peers (cid TEXT NOT NULL, peer_cid TEXT NOT NULL, username TEXT, PRIMARY KEY (cid, peer_cid))",
    "CREATE TABLE IF NOT EXISTS citadel_bytemap (cid TEXT NOT NULL, peer_cid TEXT NOT NULL, id TEXT NOT NULL, sub_id TEXT NOT NULL, bin BLOB NOT NULL, PRIMARY KEY (cid, peer_cid, id, sub_id))",
];

pub(super) const PING: &str = "SELECT 1";

// Accounts
pub(super) const UPSERT_CNAC: &str = "INSERT INTO citadel_cnacs (cid, is_personal, username, full_name, creation_date, bin) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (cid) DO UPDATE SET is_personal = excluded.is_personal, username = excluded.username, full_name = excluded.full_name, creation_date = excluded.creation_date, bin = excluded.bin";
pub(super) const SELECT_CNAC_BIN: &str = "SELECT bin FROM citadel_cnacs WHERE cid = ?";
pub(super) const SELECT_CNAC_EXISTS: &str = "SELECT cid FROM citadel_cnacs WHERE cid = ?";
pub(super) const SELECT_USERNAME: &str = "SELECT username FROM citadel_cnacs WHERE cid = ?";
pub(super) const SELECT_FULL_NAME: &str = "SELECT full_name FROM citadel_cnacs WHERE cid = ?";
pub(super) const SELECT_METADATA: &str =
    "SELECT cid, is_personal, username, full_name, creation_date FROM citadel_cnacs WHERE cid = ?";
/// `LIMIT -1` is SQLite for "no limit". CID 0 is the node's local-only account, not a client.
pub(super) const SELECT_CLIENTS_METADATA: &str = "SELECT cid, is_personal, username, full_name, creation_date FROM citadel_cnacs WHERE cid <> '0' LIMIT ?";
pub(super) const SELECT_IMPERSONAL_CIDS: &str =
    "SELECT cid FROM citadel_cnacs WHERE is_personal = 0 LIMIT ?";
pub(super) const DELETE_CNAC: &str = "DELETE FROM citadel_cnacs WHERE cid = ?";
pub(super) const DELETE_PEERS_OF_CNAC: &str =
    "DELETE FROM citadel_peers WHERE cid = ? OR peer_cid = ?";
pub(super) const DELETE_BYTEMAP_OF_CNAC: &str = "DELETE FROM citadel_bytemap WHERE cid = ?";
pub(super) const COUNT_CNACS: &str = "SELECT COUNT(*) FROM citadel_cnacs";
pub(super) const DELETE_ALL_CNACS: &str = "DELETE FROM citadel_cnacs";
pub(super) const DELETE_ALL_PEERS: &str = "DELETE FROM citadel_peers";
pub(super) const DELETE_ALL_BYTEMAP: &str = "DELETE FROM citadel_bytemap";

// Peers
/// The username is looked up from the peer's own account row, as the server knows it.
pub(super) const UPSERT_PEER_FROM_CNAC: &str = "INSERT INTO citadel_peers (cid, peer_cid, username) SELECT ?, cid, username FROM citadel_cnacs WHERE cid = ? ON CONFLICT (cid, peer_cid) DO UPDATE SET username = excluded.username";
pub(super) const UPSERT_PEER: &str = "INSERT INTO citadel_peers (cid, peer_cid, username) VALUES (?, ?, ?) ON CONFLICT (cid, peer_cid) DO UPDATE SET username = excluded.username";
pub(super) const DELETE_PEER: &str = "DELETE FROM citadel_peers WHERE cid = ? AND peer_cid = ?";
pub(super) const DELETE_PEERS_OF: &str = "DELETE FROM citadel_peers WHERE cid = ?";
pub(super) const SELECT_PEER: &str =
    "SELECT peer_cid, username FROM citadel_peers WHERE cid = ? AND peer_cid = ?";
pub(super) const SELECT_PEERS_OF: &str =
    "SELECT peer_cid, username FROM citadel_peers WHERE cid = ? ORDER BY rowid";

// Byte map
pub(super) const SELECT_BYTEMAP: &str =
    "SELECT bin FROM citadel_bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ?";
pub(super) const UPSERT_BYTEMAP: &str = "INSERT INTO citadel_bytemap (cid, peer_cid, id, sub_id, bin) VALUES (?, ?, ?, ?, ?) ON CONFLICT (cid, peer_cid, id, sub_id) DO UPDATE SET bin = excluded.bin";
pub(super) const DELETE_BYTEMAP: &str =
    "DELETE FROM citadel_bytemap WHERE cid = ? AND peer_cid = ? AND id = ? AND sub_id = ?";
pub(super) const SELECT_BYTEMAP_BY_KEY: &str =
    "SELECT sub_id, bin FROM citadel_bytemap WHERE cid = ? AND peer_cid = ? AND id = ?";
pub(super) const DELETE_BYTEMAP_BY_KEY: &str =
    "DELETE FROM citadel_bytemap WHERE cid = ? AND peer_cid = ? AND id = ?";
