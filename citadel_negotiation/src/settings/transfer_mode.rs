//! How files move between the pair: through the server (async) or directly (P2P).

use crate::ids::SettingId;
use crate::setting::{ApplyPath, Setting};
use serde::{Deserialize, Serialize};

/// Not a security order, so neither value is a downgrade of the other and glare takes the
/// Leader's value (owner decision D4).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransferMode {
    Async,
    P2p,
}

impl Setting for TransferMode {
    const ID: SettingId = SettingId::TRANSFER_MODE;
    const PERSIST: bool = false;

    fn merge(leader: &Self, _loser: &Self) -> Self {
        *leader
    }

    fn is_downgrade(_from: &Self, _to: &Self) -> Option<bool> {
        None
    }

    fn path(_from: &Self, _to: &Self) -> ApplyPath {
        ApplyPath::InBandLocal
    }

    fn is_supported(&self) -> bool {
        true
    }

    /// Nothing about a transport is costly to build: there is no bound.
    type Bound = ();

    fn exceeds(&self, _bound: &()) -> bool {
        false
    }
}
