use serde::{Deserialize, Serialize};
#[cfg(feature = "typescript")]
use ts_rs::TS;
use uuid::Uuid;

/// This is to replace a tuple for greater organization
#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct MutualPeer {
    /// The interserver cid to which `cid` belongs to
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
    pub parent_icid: u64,
    /// the client to which belongs within `parent_icid`
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
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
    #[cfg_attr(feature = "typescript", ts(type = "bigint"))]
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

/// Generates a CID given a username.
///
/// Uses SHA3-256 truncated to 64 bits rather than a non-cryptographic hash. The CID is the account
/// primary key (SQL PK / Redis key / on-disk filename), so a cheaply-craftable collision would let
/// an attacker squat or overwrite a victim's account record. With a cryptographic hash, finding any
/// collision requires ~2^32 work (birthday) and a *targeted* second preimage ~2^64; combined with
/// the registration-time existence check (a colliding username is reported as already-registered),
/// this closes the collision-driven squat/overwrite vector.
pub fn username_to_cid(username: &str) -> u64 {
    use sha3::{Digest, Sha3_256};
    let digest = Sha3_256::digest(username.as_bytes());
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA3-256 digest is always 32 bytes"),
    )
}

/// A convenience wrapper for passing arguments to functions that require searches for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum UserIdentifier {
    /// Raw user ID
    ID(#[cfg_attr(feature = "typescript", ts(type = "bigint"))] u64),
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

#[cfg(test)]
mod cid_tests {
    use super::username_to_cid;

    #[test]
    fn deterministic_and_distinct() {
        // Same username always maps to the same CID.
        assert_eq!(username_to_cid("alice"), username_to_cid("alice"));
        // Different usernames map to different CIDs.
        assert_ne!(username_to_cid("alice"), username_to_cid("bob"));
        // Near-identical usernames don't share a CID (avalanche of a crypto hash).
        assert_ne!(username_to_cid("alice"), username_to_cid("alicf"));
        assert_ne!(username_to_cid("user"), username_to_cid("user "));
    }

    #[test]
    fn nonzero_for_typical_usernames() {
        // CID 0 is treated as invalid at registration; ensure typical usernames don't collide to it.
        for name in ["a", "alice", "bob", "server-admin", "user@example.com"] {
            assert_ne!(
                username_to_cid(name),
                0,
                "{name:?} hashed to reserved CID 0"
            );
        }
    }
}
