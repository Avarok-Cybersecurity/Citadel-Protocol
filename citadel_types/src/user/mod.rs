use serde::{Deserialize, Serialize};
use std::hash::Hasher;
#[cfg(feature = "typescript")]
use ts_rs::TS;
use uuid::Uuid;

/// This is to replace a tuple for greater organization
#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct MutualPeer {
    /// The interserver cid to which `cid` belongs to
    pub parent_icid: u64,
    /// the client to which belongs within `parent_icid`
    pub cid: u64,
    /// The username of this peer
    pub username: Option<String>,
}

/// Contains info about a peer, used for giving the user access to usernames and names of peers
#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct PeerInfo {
    /// the client to which belongs within `parent_icid`
    pub cid: u64,
    /// The username of this peer
    pub username: String,
    /// The full name of this peer
    pub full_name: String,
}

impl PartialEq for MutualPeer {
    fn eq(&self, other: &Self) -> bool {
        self.parent_icid == other.parent_icid
            && self.cid == other.cid
            && self.username.as_ref() == other.username.as_ref()
    }
}

/// Generates a CID given a username
pub fn username_to_cid(username: &str) -> u64 {
    let mut hasher = twox_hash::XxHash64::default();
    hasher.write(username.as_bytes());
    hasher.finish()
}

/// A convenience wrapper for passing arguments to functions that require searches for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum UserIdentifier {
    /// Raw user ID
    ID(u64),
    /// Username connected by an unspecified ID
    Username(String),
}

impl From<String> for UserIdentifier {
    fn from(username: String) -> Self {
        Self::Username(username)
    }
}

impl From<&str> for UserIdentifier {
    fn from(username: &str) -> Self {
        Self::Username(username.to_string())
    }
}

impl From<u64> for UserIdentifier {
    fn from(cid: u64) -> Self {
        Self::ID(cid)
    }
}

impl From<Uuid> for UserIdentifier {
    fn from(uuid: Uuid) -> Self {
        Self::Username(uuid.to_string())
    }
}
