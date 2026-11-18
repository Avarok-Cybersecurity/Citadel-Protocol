//! Media-lane accounting (owner decision, §14): media frames are never returned, only dropped
//! and zeroised, but a true close says, per stream, what was lost, so the kernel or the app can
//! restart or resync the stream. Metadata only: no payload bytes, no addresses.

use std::collections::{BTreeMap, VecDeque};

pub use citadel_media::frame::{TrackId, TrackKind};
pub use citadel_negotiation::settings::MediaTransportKind;

use crate::path::RouteKind;

/// A media stream as the ledger knows it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MediaStream {
    pub track: TrackId,
    pub kind: TrackKind,
    /// The codec or profile id (`MediaTrackDescriptor::codec`).
    pub codec: [u8; 4],
    /// The media lane: the session UDP channel or the reliable channel.
    pub lane: MediaTransportKind,
}

/// One frame, by its sequence and capture timestamp (`FrameHeader::{sequence, timestamp}`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FramePoint {
    pub sequence: u32,
    pub timestamp: u32,
}

/// What one stream lost when its link truly closed. Exactly one per stream the link carried.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MediaLoss {
    pub stream: MediaStream,
    /// The route the stream last rode; `None` if it never rode one.
    pub route: Option<RouteKind>,
    /// The last frame confirmed delivered.
    pub last_confirmed: Option<FramePoint>,
    /// The last frame handed to the SDK.
    pub last_handed: Option<FramePoint>,
    /// Frames dropped: by the queue, by a lost path, or still queued at the close.
    pub dropped: u64,
    /// The capture timestamps of the first and the last dropped frame.
    pub dropped_span: Option<(u32, u32)>,
    /// The receiver must wait for a keyframe (or resync its decoder) to resume: a video stream
    /// that lost a frame after its last confirmed one.
    pub needs_resync: bool,
}

#[derive(Clone, Debug)]
pub(super) struct StreamBook {
    pub(super) stream: MediaStream,
    pub(super) route: Option<RouteKind>,
    pub(super) last_confirmed: Option<FramePoint>,
    pub(super) last_handed: Option<FramePoint>,
    /// Handed and not yet confirmed or dropped, in sequence order.
    pub(super) pending: VecDeque<FramePoint>,
    pub(super) dropped: u64,
    pub(super) dropped_span: Option<(u32, u32)>,
}

/// The per-link media accounting.
#[derive(Clone, Debug)]
pub struct MediaLedger {
    pub(super) streams: BTreeMap<TrackId, StreamBook>,
}
