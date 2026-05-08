//! Signaling service abstraction for serverless browser-to-browser connections.
//!
//! Provides the [`SignalingService`] trait for out-of-band signaling backends
//! (e.g., Firebase RTDB) and helpers for deterministic role assignment between
//! two browser peers.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::proto::peer::peer_crypt::IceCandidateData;

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("hex write");
    }
    s
}

/// Room identifier derived from a shared token.
pub struct RoomId(pub String);

/// Object-safe trait abstracting an out-of-band signaling backend.
///
/// Implementations must provide key-value publish/read semantics scoped
/// to a room. The signaling service is only used during connection setup;
/// once the WebRTC DataChannel opens, signaling is no longer needed.
pub trait SignalingService: 'static {
    /// Publish a JSON value at `{room}/{key}`.
    fn publish(
        &self,
        room: &str,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>>>>;

    /// Read the JSON value at `{room}/{key}`. Returns `None` if absent.
    fn read(
        &self,
        room: &str,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Option<serde_json::Value>>>>>;

    /// List all children under `{room}/{prefix}` as a key-value map.
    fn list_children(
        &self,
        room: &str,
        prefix: &str,
    ) -> Pin<Box<dyn Future<Output = io::Result<HashMap<String, serde_json::Value>>>>>;

    /// Delete an entire room and all its children.
    fn delete_room(&self, room: &str) -> Pin<Box<dyn Future<Output = io::Result<()>>>>;
}

/// Hello message published during peer discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    pub identity_hash: String,
    pub nonce: Vec<u8>,
}

/// SDP + ICE candidates exchanged during WebRTC setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdpExchange {
    pub sdp: String,
    pub ice_candidates: Vec<IceCandidateData>,
}

/// Derive a room ID from a shared token.
///
/// `room_id = hex(SHA3-256("citadel-room-v1" || token))[0..32]`
pub fn derive_room_id(room_token: &[u8]) -> RoomId {
    let mut hasher = Sha3_256::new();
    hasher.update(b"citadel-room-v1");
    hasher.update(room_token);
    let hash = hasher.finalize();
    RoomId(to_hex(&hash[..16]))
}

/// Compute an identity hash for role determination.
///
/// `identity_hash = hex(SHA3-256("citadel-id-v1" || nonce || token))`
pub fn compute_identity_hash(nonce: &[u8], room_token: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b"citadel-id-v1");
    hasher.update(nonce);
    hasher.update(room_token);
    to_hex(&hasher.finalize())
}

/// Determine whether this peer should assume the server role.
///
/// The peer with the lexicographically higher identity hash becomes
/// the server (Alpha). Returns `true` if `my_hash > their_hash`.
pub fn determine_is_server(my_hash: &str, their_hash: &str) -> bool {
    my_hash > their_hash
}
