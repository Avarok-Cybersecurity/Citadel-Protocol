//! The wire: what one negotiator sends the other.
//!
//! Every per-setting frame travels in an [`Envelope`] numbered per direction. The receiver
//! processes envelopes strictly in that order (buffering a bounded gap, dropping duplicates), so
//! the state machine sees the sender's frames in the order they were sent whatever the lane
//! does. That one mechanism is what makes duplication and reordering harmless.
//! [`Hello`] is per channel, not per setting: the shell reads it to construct the negotiators.

use crate::ids::{Epoch, SettingId};
use serde::{Deserialize, Deserializer, Serialize};

/// One frame of one setting's negotiation, numbered in its direction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub setting: SettingId,
    /// The sender's frame counter for this setting, from 0 on a new channel.
    pub n: u64,
    pub frame: Frame,
}

/// What a negotiator says. Values are the setting's own bincode bytes, so this layer never
/// depends on the setting types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    /// "Move this setting from epoch `from_epoch` to `value`."
    Propose {
        from_epoch: Epoch,
        seq: u32,
        value: Vec<u8>,
    },
    /// The answer that agrees; `agreed` echoes the proposed bytes.
    Accept {
        from_epoch: Epoch,
        seq: u32,
        agreed: Vec<u8>,
    },
    /// The answer that refuses.
    Reject {
        from_epoch: Epoch,
        seq: u32,
        reason: RejectReason,
    },
    /// "I applied `epoch`"; both sides compare evidence before calling it done.
    Applied {
        epoch: Epoch,
        evidence: ApplyEvidence,
    },
    /// "I will send nothing more under `epoch`": the receiver may raise its floor past it.
    Retire { epoch: Epoch },
    /// The proposer withdraws. It loses to an answer already given: the peer answers every
    /// proposal on receipt, so in v1 a cancel never overtakes its proposal and is advisory.
    Cancel { from_epoch: Epoch, seq: u32 },
    /// Precedes a deliberate drop, so the peer never mistakes it for a lost link.
    Renegotiate {
        reason: RenegotiationReason,
        next: Vec<u8>,
    },
}

/// What both sides compare after applying an epoch.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApplyEvidence {
    /// The toolset version that carries a key epoch; `None` for a locally applied setting.
    pub version: Option<u32>,
    /// SHA3-256 of the agreed value's bytes.
    pub digest: [u8; 32],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RejectReason {
    /// Below the receiver's minimum, or a lowering its policy does not allow (D7).
    BelowPolicy,
    Unauthorized,
    /// A stronger proposal won the glare; the agreed value is reported separately.
    Superseded,
    /// Proposed from an epoch the receiver has already left.
    Stale,
    /// The receiver (or the local side) is mid-negotiation for this setting.
    Busy,
    TimedOut,
    /// A value this build cannot read or will not negotiate.
    Unsupported,
    /// Both sides proposed at once and the merge would lower the setting: glare never lowers.
    Crossed,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RenegotiationReason {
    HandshakeRequired(SettingId),
    ApplyFailed(SettingId),
    PeerLegacy,
    Desync,
}

/// A set of capability bits for one setting in a [`Hello`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityBits(pub u32);

impl CapabilityBits {
    /// The peer negotiates this setting in band.
    pub const IN_BAND: CapabilityBits = CapabilityBits(1);

    pub fn contains(self, other: CapabilityBits) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Whether the peer can negotiate a setting in band.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PeerSupport {
    InBand,
    /// No in-channel lane for this setting: every change is a deliberate drop and redial.
    Legacy,
}

/// The first frame on a new channel, both ways.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol: u32,
    pub settings: Vec<(SettingId, CapabilityBits)>,
}

impl Hello {
    /// What this Hello says about one setting. A setting it does not list is legacy.
    pub fn support_for(&self, setting: SettingId) -> PeerSupport {
        let in_band = self
            .settings
            .iter()
            .any(|(id, bits)| *id == setting && bits.contains(CapabilityBits::IN_BAND));
        if in_band {
            PeerSupport::InBand
        } else {
            PeerSupport::Legacy
        }
    }
}

/// A frame that could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameCodecError(pub String);

/// Bincode, like every `PeerSignal`. A reader ignores trailing bytes, which is what lets a later
/// version append fields (see [`appended_field`]).
pub fn encode<T: Serialize>(item: &T) -> Result<Vec<u8>, FrameCodecError> {
    bincode::serialize(item).map_err(|err| FrameCodecError(err.to_string()))
}

pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, FrameCodecError> {
    citadel_io::decode::deserialize(bytes).map_err(|err| FrameCodecError(err.to_string()))
}

/// For a trailing field added after v1: `#[serde(default, deserialize_with = "appended_field")]`.
/// A v1 frame has no bytes for it and reads as `None`. The same convention as `PeerSignal`
/// (`citadel_proto/src/proto/peer/peer_layer.rs`).
pub fn appended_field<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer).ok().flatten())
}
