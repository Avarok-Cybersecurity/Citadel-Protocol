use super::eos::EosTracker;
use super::transport::{BoxedSource, MediaTransportKind};
use citadel_io::time::{sleep_until, Duration, Instant};
use citadel_io::ErrorCode;
use citadel_media::{
    ControlMessage, JitterBuffer, MediaConfig, MediaFrame, MediaInstant, MediaStats,
    MediaTrackDescriptor, PopResult, PushResult, ReassembleOutcome, Reassembler, TrackId,
};
use citadel_proto::prelude::{NetworkError, SecBuffer};
use futures::stream::{select_all, SelectAll};
use futures::StreamExt;
use std::collections::VecDeque;

/// What [`MediaReceiver::next_event`] yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaEvent {
    /// The peer announced (or accepted) these tracks.
    Tracks(Vec<MediaTrackDescriptor>),
    /// A frame in sequence order for its track.
    Frame(MediaFrame),
    /// Frames `missing_from..=missing_to` on `track` were skipped; the next
    /// event is the frame that follows the gap.
    Gap {
        track: TrackId,
        missing_from: u32,
        missing_to: u32,
    },
    /// The peer finished `track`.
    EndOfStream(TrackId),
    /// A transport stream ended; no further events will follow.
    Closed,
}

enum Input {
    Datagram(Option<SecBuffer>),
    Deadline,
}

/// Inbound half of a media endpoint.
///
/// Owns the transport receive halves. In unreliable mode that includes the UDP
/// receive half, so dropping this receiver signals `DisconnectUDP` to the peer.
pub struct MediaReceiver {
    kind: MediaTransportKind,
    /// Media and control lanes merged; ends only once every lane has ended.
    lanes: SelectAll<BoxedSource>,
    reassembler: Reassembler,
    jitter: JitterBuffer,
    /// Events decoded ahead of delivery (frame following a gap, control).
    ready: VecDeque<MediaEvent>,
    /// End-of-stream announcements waiting for their track to fully drain.
    eos: EosTracker,
    start: Instant,
    closed: bool,
    stats: MediaStats,
}

impl std::fmt::Debug for MediaReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaReceiver")
            .field("kind", &self.kind)
            .field("closed", &self.closed)
            .field("stats", &self.stats)
            .finish()
    }
}

impl MediaReceiver {
    pub(crate) fn new(
        kind: MediaTransportKind,
        media: BoxedSource,
        control: Option<BoxedSource>,
        config: MediaConfig,
        start: Instant,
    ) -> Result<Self, NetworkError> {
        Ok(Self {
            kind,
            lanes: select_all(std::iter::once(media).chain(control)),
            reassembler: Reassembler::new(config).map_err(super::error::from_media_error)?,
            jitter: JitterBuffer::new(config).map_err(super::error::from_media_error)?,
            ready: VecDeque::new(),
            eos: EosTracker::new(config.jitter_depth_micros),
            start,
            closed: false,
            stats: MediaStats::new(),
        })
    }

    pub fn kind(&self) -> MediaTransportKind {
        self.kind
    }

    pub fn stats(&self) -> MediaStats {
        self.stats
    }

    /// The only place wall time is read for the inbound media path.
    fn now(&self) -> MediaInstant {
        MediaInstant::from_micros(self.start.elapsed().as_micros() as u64)
    }

    fn to_instant(&self, at: MediaInstant) -> Instant {
        self.start + Duration::from_micros(at.as_micros())
    }

    /// Waits for the next event. After [`MediaEvent::Closed`] every call
    /// returns `Closed` again.
    pub async fn next_event(&mut self) -> MediaEvent {
        loop {
            if let Some(event) = self.ready.pop_front() {
                return event;
            }
            if let Some(event) = self.pop_jitter() {
                return event;
            }
            if self.resolve_eos(false) {
                continue;
            }
            if self.closed {
                // Flush frames still parked behind a gap before reporting closure.
                match self.jitter.next_deadline() {
                    Some(at) if self.jitter.buffered_len() > 0 => {
                        sleep_until(self.to_instant(at)).await;
                        continue;
                    }
                    _ => {}
                }
                // No more input can arrive: expire pending end-of-stream
                // records now instead of waiting out their deadlines.
                if self.resolve_eos(true) {
                    continue;
                }
                return MediaEvent::Closed;
            }
            match self.wait_input().await {
                Input::Datagram(Some(buf)) => self.ingest(buf.as_ref()),
                Input::Datagram(None) => self.closed = true,
                Input::Deadline => {
                    let now = self.now();
                    self.stats.frames_evicted_incomplete +=
                        self.reassembler.evict_stale(now) as u64;
                }
            }
        }
    }

    /// Bridges [`EosTracker::resolve`] to this receiver's state.
    fn resolve_eos(&mut self, force: bool) -> bool {
        let now = self.now();
        let Self {
            eos,
            jitter,
            ready,
            stats,
            ..
        } = self;
        eos.resolve(
            now,
            force,
            |track| jitter.next_expected(track),
            ready,
            stats,
        )
    }

    fn pop_jitter(&mut self) -> Option<MediaEvent> {
        let now = self.now();
        match self.jitter.pop_ready(now) {
            PopResult::Frame(frame) => {
                self.stats.frames_delivered += 1;
                Some(MediaEvent::Frame(frame))
            }
            PopResult::Gap {
                track,
                missing_from,
                missing_to,
                next,
            } => {
                self.stats.gaps_skipped += 1;
                self.stats.frames_missing +=
                    u64::from(missing_to.wrapping_sub(missing_from).wrapping_add(1));
                self.stats.frames_delivered += 1;
                self.ready.push_back(MediaEvent::Frame(next));
                Some(MediaEvent::Gap {
                    track,
                    missing_from,
                    missing_to,
                })
            }
            PopResult::NotReady => None,
        }
    }

    async fn wait_input(&mut self) -> Input {
        let deadline = self
            .jitter
            .next_deadline()
            .into_iter()
            .chain(self.eos.next_deadline())
            .min()
            .map(|at| self.to_instant(at));
        let timer = async move {
            match deadline {
                Some(at) => sleep_until(at).await,
                None => futures::future::pending().await,
            }
        };
        citadel_io::tokio::select! {
            item = self.lanes.next() => Input::Datagram(item),
            _ = timer => Input::Deadline,
        }
    }

    fn ingest(&mut self, datagram: &[u8]) {
        let now = self.now();
        self.stats.fragments_received += 1;
        self.stats.bytes_received += datagram.len() as u64;
        match self.reassembler.push(datagram, now) {
            ReassembleOutcome::Complete(frame) => {
                self.stats.frames_completed += 1;
                match self.jitter.push(frame, now) {
                    PushResult::Buffered => {}
                    PushResult::Late => self.stats.frames_late += 1,
                    PushResult::TooOld => self.stats.frames_too_old += 1,
                    PushResult::Duplicate => self.stats.fragments_duplicate += 1,
                }
            }
            ReassembleOutcome::Partial { .. } => {}
            ReassembleOutcome::Duplicate => self.stats.fragments_duplicate += 1,
            ReassembleOutcome::Control(body) => match Self::decode_control(&body) {
                Ok(ControlMessage::AnnounceTracks(list) | ControlMessage::AcceptTracks(list)) => {
                    self.ready.push_back(MediaEvent::Tracks(list))
                }
                Ok(ControlMessage::EndOfStream { track, frames_sent }) => {
                    self.eos.record(track, frames_sent, now)
                }
                Err(err) => {
                    self.stats.fragments_rejected += 1;
                    log::warn!(target: "citadel", "{err}");
                }
            },
            ReassembleOutcome::Rejected(err) => {
                self.stats.fragments_rejected += 1;
                log::debug!(target: "citadel", "media fragment rejected: {err}");
            }
        }
    }

    fn decode_control(body: &[u8]) -> Result<ControlMessage, NetworkError> {
        ControlMessage::decode(body)
            .map_err(|err| citadel_io::error!(ErrorCode::MediaControlDecode, err))
    }
}
