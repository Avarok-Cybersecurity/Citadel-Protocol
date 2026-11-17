//! One P2P connection's key-epoch surface, as `PeerChannel::key_epoch` hands it out.

use super::bound_frame::{self, OpenError};
use super::floor::{Floor, FloorViolation, MessageFloor};
use crate::error::NetworkError;
use crate::ProtocolRatchetManager;
use citadel_crypt::ratchets::key_epoch::{profile_of, KeyEpochTag};
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::mpsc::UnboundedReceiver;
use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::{ConnectionId, Envelope};
use std::sync::Arc;

/// One P2P connection's key-epoch surface: its ratchet manager, its message floor and its id.
#[derive(Clone)]
pub struct KeyEpochHandle<R: Ratchet> {
    pub(super) manager: ProtocolRatchetManager<R>,
    pub(super) floor: Arc<MessageFloor>,
    pub(super) connection: ConnectionId,
}

impl<R: Ratchet> std::fmt::Debug for KeyEpochHandle<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEpochHandle")
            .field("connection", &self.connection)
            .field("floor", &self.floor.get())
            .finish()
    }
}

impl<R: Ratchet> KeyEpochHandle<R> {
    pub(crate) fn new(
        manager: ProtocolRatchetManager<R>,
        floor: Arc<MessageFloor>,
        connection: ConnectionId,
    ) -> Self {
        Self {
            manager,
            floor,
            connection,
        }
    }

    pub fn connection_id(&self) -> ConnectionId {
        self.connection
    }

    /// The profile the connection's newest usable ratchet carries (the getter, from the ratchet
    /// itself rather than from what was asked for).
    pub fn negotiated(&self) -> Option<KeyProfile> {
        profile_of(&self.manager.get_ratchet(None)?).ok()
    }

    /// The newest usable ratchet version.
    pub fn current_version(&self) -> u32 {
        self.manager.session_crypto_state().latest_usable_version()
    }

    /// The epoch toolset version `version` was built for; `None` for a plain version.
    pub fn epoch_of(&self, version: u32) -> Option<KeyEpochTag> {
        self.manager.epoch_of(version)
    }

    /// Whether the toolset still holds `version`: C2/C3, a frame decrypts only under its own.
    pub fn holds_version(&self, version: u32) -> bool {
        self.manager.get_ratchet(Some(version)).is_some()
    }

    pub fn floor(&self) -> Option<Floor> {
        self.floor.get()
    }

    /// Every message frame the floor refused (`None` after the first call).
    pub fn take_violations(&self) -> Option<UnboundedReceiver<FloorViolation>> {
        self.floor.take_violations()
    }

    /// C7: seals a negotiation envelope for this connection under the newest usable version.
    pub fn seal_frame(&self, envelope: &Envelope) -> Result<Vec<u8>, NetworkError> {
        let ratchet = self
            .manager
            .get_ratchet(None)
            .ok_or_else(|| NetworkError::msg("the connection has no usable ratchet"))?;
        bound_frame::seal(&ratchet, self.connection, envelope)
    }

    /// C7: opens a frame sealed for this connection, under the version it names.
    pub fn open_frame(&self, bytes: &[u8]) -> Result<Envelope, OpenError> {
        bound_frame::open(
            |version| self.manager.get_ratchet(Some(version)),
            self.connection,
            bytes,
        )
    }
}
