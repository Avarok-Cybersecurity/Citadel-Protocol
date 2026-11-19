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

/// Whether `a` is at or before `b` in a stream's (wrapping) sequence space.
fn at_or_before(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) >= 0
}

impl StreamBook {
    fn drop_frame(&mut self, frame: FramePoint) {
        self.dropped += 1;
        self.dropped_span = Some(match self.dropped_span {
            None => (frame.timestamp, frame.timestamp),
            Some((first, _)) => (first, frame.timestamp),
        });
    }

    fn loss(&self) -> MediaLoss {
        MediaLoss {
            stream: self.stream,
            route: self.route,
            last_confirmed: self.last_confirmed,
            last_handed: self.last_handed,
            dropped: self.dropped,
            dropped_span: self.dropped_span,
            needs_resync: self.stream.kind == TrackKind::Video && self.dropped > 0,
        }
    }
}

impl MediaLedger {
    /// A ledger with no stream yet.
    pub fn empty() -> Self {
        MediaLedger {
            streams: BTreeMap::new(),
        }
    }

    /// A stream started on this link. Opening a track again keeps its counts.
    pub fn open(&mut self, stream: MediaStream) {
        self.streams
            .entry(stream.track)
            .and_modify(|book| book.stream = stream)
            .or_insert(StreamBook {
                stream,
                route: None,
                last_confirmed: None,
                last_handed: None,
                pending: VecDeque::new(),
                dropped: 0,
                dropped_span: None,
            });
    }

    /// Every open stream now rides `route`.
    pub fn rode(&mut self, route: RouteKind) {
        for book in self.streams.values_mut() {
            book.route = Some(route);
        }
    }

    /// A frame was handed to the SDK. `false` for a track that was never opened.
    pub fn handed(&mut self, track: TrackId, frame: FramePoint) -> bool {
        let Some(book) = self.streams.get_mut(&track) else {
            return false;
        };
        book.last_handed = Some(frame);
        book.pending.push_back(frame);
        true
    }

    /// Every frame up to `upto` was confirmed delivered.
    pub fn confirmed(&mut self, track: TrackId, upto: FramePoint) {
        let Some(book) = self.streams.get_mut(&track) else {
            return;
        };
        while let Some(front) = book.pending.front() {
            if !at_or_before(front.sequence, upto.sequence) {
                break;
            }
            book.pending.pop_front();
        }
        book.last_confirmed = Some(upto);
    }

    /// The queue or the pump dropped one frame.
    pub fn dropped(&mut self, track: TrackId, sequence: u32) {
        let Some(book) = self.streams.get_mut(&track) else {
            return;
        };
        if let Some(i) = book.pending.iter().position(|f| f.sequence == sequence) {
            if let Some(frame) = book.pending.remove(i) {
                book.drop_frame(frame);
            }
        }
    }

    /// The path died: media is never replayed, so every frame in flight is dropped.
    pub fn path_lost(&mut self) {
        for book in self.streams.values_mut() {
            while let Some(frame) = book.pending.pop_front() {
                book.drop_frame(frame);
            }
        }
    }

    /// Frames dropped so far, over every stream.
    pub fn dropped_total(&self) -> u64 {
        self.streams.values().map(|b| b.dropped).sum()
    }

    /// A true close: one loss record per stream, every frame still in flight counted dropped.
    pub fn close(&mut self) -> Vec<MediaLoss> {
        self.path_lost();
        std::mem::take(&mut self.streams)
            .values()
            .map(StreamBook::loss)
            .collect()
    }
}
