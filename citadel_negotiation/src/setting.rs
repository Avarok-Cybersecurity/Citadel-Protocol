//! What a negotiable setting must say about itself.

use crate::ids::SettingId;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha3::{Digest, Sha3_256};
use std::fmt::Debug;

/// How a change from one value to another is carried out on a live connection.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ApplyPath {
    /// One steered ratchet round, triggered by the Leader, *is* the new epoch.
    InBandKeyEpoch,
    /// Each side applies the value locally and confirms.
    InBandLocal,
    /// The change cannot be made on this connection: deliberate drop and redial.
    Handshake,
}

/// A value two peers can negotiate on a live connection.
///
/// `merge` is called with the same `(leader, loser)` assignment on both ends (the role is fixed
/// per pair, [`Role`](crate::Role)), so both compute the same agreed value from the same inputs.
/// It must be associative and idempotent. For an *ordered* setting (`is_downgrade` returns
/// `Some`) it must also be commutative and its result must never be weaker than either input:
/// that is what makes glare unable to downgrade. An unordered setting may pick the leader's.
pub trait Setting: Clone + Eq + Debug + Serialize + DeserializeOwned + Send + 'static {
    /// The registry id ([`SettingId`]); never reused.
    const ID: SettingId;
    /// Whether the agreed value is persisted through the `EpochStore` port.
    const PERSIST: bool;
    /// The value both sides take when their proposals cross.
    fn merge(leader: &Self, loser: &Self) -> Self;
    /// Whether `to` is weaker than `from`; `None` for an unordered setting.
    fn is_downgrade(from: &Self, to: &Self) -> Option<bool>;
    /// How the change from `from` to `to` is applied.
    fn path(from: &Self, to: &Self) -> ApplyPath;
    /// Whether this value may be negotiated at all (for keys: post-quantum suites only).
    fn is_supported(&self) -> bool;
}

/// A value that could not be encoded or decoded as the setting's wire bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueCodecError(pub String);

/// The setting's own wire bytes (bincode, like every `PeerSignal`).
pub fn encode_value<S: Setting>(value: &S) -> Result<Vec<u8>, ValueCodecError> {
    bincode::serialize(value).map_err(|err| ValueCodecError(err.to_string()))
}

/// Reads a value the peer sent.
pub fn decode_value<S: Setting>(bytes: &[u8]) -> Result<S, ValueCodecError> {
    citadel_io::decode::deserialize(bytes).map_err(|err| ValueCodecError(err.to_string()))
}

/// SHA3-256 of a value's wire bytes: the evidence both sides compare after applying.
pub fn value_digest(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

/// Whether `value` is below `minimum` under the setting's order (never, for an unordered one).
pub fn is_below<S: Setting>(minimum: &S, value: &S) -> bool {
    S::is_downgrade(minimum, value) == Some(true)
}
