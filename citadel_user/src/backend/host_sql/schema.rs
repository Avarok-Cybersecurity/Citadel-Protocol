//! The tables, and every statement the backend runs against them (SQLite dialect).
//!
//! CIDs are decimal TEXT: they span the whole u64 range, which neither SQLite's signed
//! INTEGER nor a JS number can hold. The primary keys are what give the backend its
//! semantics — the SQL backend lacked them and so grew duplicate rows (#305, #306, #307).
//! Table names carry a `citadel_` prefix so a host can keep tables of its own beside them.

/// Every statement is `IF NOT EXISTS`, so running them at each `connect` is also the migration:
/// a store created before a table existed gains it, empty, the next time its node starts.
///
/// RE-VFS objects (see `revfs`): `citadel_revfs_files` maps an account's virtual path to the
/// upload that holds its bytes, `citadel_revfs_chunks` holds those bytes in bounded rows keyed by
/// upload and index, and `citadel_revfs_uploads` is the staging record of an upload in flight.
/// `group_bytes` is the length of the object's first group as it arrived. The client encrypted
/// each group on its own, so the object can only be sent back in groups of exactly that size.
/// Upload ids are unique per upload, so a replacement stages beside the object it replaces and
/// swaps in with one transaction.
pub(super) const CREATE_TABLES: [&str; 6] = [
    "CREATE TABLE IF NOT EXISTS citadel_cnacs (cid TEXT NOT NULL PRIMARY KEY, is_personal INTEGER NOT NULL, username TEXT NOT NULL, full_name TEXT NOT NULL, creation_date TEXT NOT NULL, bin BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS citadel_peers (cid TEXT NOT NULL, peer_cid TEXT NOT NULL, username TEXT, PRIMARY KEY (cid, peer_cid))",
    "CREATE TABLE IF NOT EXISTS citadel_bytemap (cid TEXT NOT NULL, peer_cid TEXT NOT NULL, id TEXT NOT NULL, sub_id TEXT NOT NULL, bin BLOB NOT NULL, PRIMARY KEY (cid, peer_cid, id, sub_id))",
    "CREATE TABLE IF NOT EXISTS citadel_revfs_files (cid TEXT NOT NULL, path TEXT NOT NULL, upload TEXT NOT NULL, size INTEGER NOT NULL, chunks INTEGER NOT NULL, group_bytes INTEGER NOT NULL, metadata BLOB NOT NULL, PRIMARY KEY (cid, path))",
    "CREATE TABLE IF NOT EXISTS citadel_revfs_uploads (upload TEXT NOT NULL PRIMARY KEY, cid TEXT NOT NULL, path TEXT NOT NULL, bytes INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS citadel_revfs_chunks (upload TEXT NOT NULL, idx INTEGER NOT NULL, bin BLOB NOT NULL, PRIMARY KEY (upload, idx))",
];

/// A node that starts has no transfer in flight, so every staged upload is abandoned: its rows
/// would otherwise count against the quota forever. Run at `connect`, after `CREATE_TABLES`.
pub(super) const DISCARD_ABANDONED_UPLOADS: [&str; 2] = [
    "DELETE FROM citadel_revfs_chunks WHERE upload IN (SELECT upload FROM citadel_revfs_uploads)",
    "DELETE FROM citadel_revfs_uploads",
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
pub(super) const DELETE_REVFS_CHUNKS_OF_CNAC: &str = "DELETE FROM citadel_revfs_chunks WHERE upload IN (SELECT upload FROM citadel_revfs_files WHERE cid = ? UNION SELECT upload FROM citadel_revfs_uploads WHERE cid = ?)";
pub(super) const DELETE_REVFS_FILES_OF_CNAC: &str = "DELETE FROM citadel_revfs_files WHERE cid = ?";
pub(super) const DELETE_REVFS_UPLOADS_OF_CNAC: &str =
    "DELETE FROM citadel_revfs_uploads WHERE cid = ?";
pub(super) const COUNT_CNACS: &str = "SELECT COUNT(*) FROM citadel_cnacs";
pub(super) const DELETE_ALL_CNACS: &str = "DELETE FROM citadel_cnacs";
pub(super) const DELETE_ALL_PEERS: &str = "DELETE FROM citadel_peers";
pub(super) const DELETE_ALL_BYTEMAP: &str = "DELETE FROM citadel_bytemap";
pub(super) const DELETE_ALL_REVFS_CHUNKS: &str = "DELETE FROM citadel_revfs_chunks";
pub(super) const DELETE_ALL_REVFS_FILES: &str = "DELETE FROM citadel_revfs_files";
pub(super) const DELETE_ALL_REVFS_UPLOADS: &str = "DELETE FROM citadel_revfs_uploads";

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

// RE-VFS
pub(super) const INSERT_REVFS_UPLOAD: &str =
    "INSERT INTO citadel_revfs_uploads (upload, cid, path, bytes) VALUES (?, ?, ?, 0)";
/// Bytes the backend holds or is staging, leaving out the object at `(cid, path)`, which the
/// upload asking will replace: params `cid, path`.
pub(super) const SELECT_REVFS_USAGE_EXCEPT: &str = "SELECT (SELECT COALESCE(SUM(size), 0) FROM citadel_revfs_files WHERE NOT (cid = ? AND path = ?)) + (SELECT COALESCE(SUM(bytes), 0) FROM citadel_revfs_uploads)";
/// params `upload, idx, bin`
pub(super) const INSERT_REVFS_CHUNK: &str =
    "INSERT INTO citadel_revfs_chunks (upload, idx, bin) VALUES (?, ?, ?) RETURNING idx";
/// The quota check and the insert in one statement, so two uploads cannot both pass the check
/// for the same room: params `upload, idx, bin, cid, path, len(bin), quota`. No row back means
/// the chunk did not fit.
pub(super) const INSERT_REVFS_CHUNK_WITHIN_QUOTA: &str = "INSERT INTO citadel_revfs_chunks (upload, idx, bin) SELECT ?, ?, ? WHERE (SELECT COALESCE(SUM(size), 0) FROM citadel_revfs_files WHERE NOT (cid = ? AND path = ?)) + (SELECT COALESCE(SUM(bytes), 0) FROM citadel_revfs_uploads) + ? <= ? RETURNING idx";
/// params `len, upload, upload, idx`: counts the chunk only if it was stored.
pub(super) const ADD_REVFS_UPLOAD_BYTES: &str = "UPDATE citadel_revfs_uploads SET bytes = bytes + ? WHERE upload = ? AND EXISTS (SELECT 1 FROM citadel_revfs_chunks WHERE upload = ? AND idx = ?)";
/// Commit, part 1: the replaced object's chunks, if the upload is still staged. Params `cid, path, upload`.
pub(super) const DELETE_REPLACED_REVFS_CHUNKS: &str = "DELETE FROM citadel_revfs_chunks WHERE upload IN (SELECT upload FROM citadel_revfs_files WHERE cid = ? AND path = ?) AND EXISTS (SELECT 1 FROM citadel_revfs_uploads WHERE upload = ?)";
/// Commit, part 2: point the path at the upload. Params `cid, path, upload, size, chunks, group_bytes, metadata, upload`.
pub(super) const UPSERT_REVFS_FILE: &str = "INSERT INTO citadel_revfs_files (cid, path, upload, size, chunks, group_bytes, metadata) SELECT ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM citadel_revfs_uploads WHERE upload = ?) ON CONFLICT (cid, path) DO UPDATE SET upload = excluded.upload, size = excluded.size, chunks = excluded.chunks, group_bytes = excluded.group_bytes, metadata = excluded.metadata";
/// Commit, part 3, and abort: the staging record. A row back means the upload was still staged.
pub(super) const DELETE_REVFS_UPLOAD: &str =
    "DELETE FROM citadel_revfs_uploads WHERE upload = ? RETURNING upload";
pub(super) const DELETE_REVFS_UPLOAD_CHUNKS: &str =
    "DELETE FROM citadel_revfs_chunks WHERE upload = ?";
pub(super) const SELECT_REVFS_FILE: &str =
    "SELECT upload, size, chunks, group_bytes, metadata FROM citadel_revfs_files WHERE cid = ? AND path = ?";
pub(super) const SELECT_REVFS_CHUNK: &str =
    "SELECT bin FROM citadel_revfs_chunks WHERE upload = ? AND idx = ?";
pub(super) const DELETE_REVFS_FILE_CHUNKS: &str = "DELETE FROM citadel_revfs_chunks WHERE upload IN (SELECT upload FROM citadel_revfs_files WHERE cid = ? AND path = ?)";
pub(super) const DELETE_REVFS_FILE: &str =
    "DELETE FROM citadel_revfs_files WHERE cid = ? AND path = ? RETURNING upload";
