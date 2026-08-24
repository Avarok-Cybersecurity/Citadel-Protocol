use super::error::MediaResultExt;
use super::transport::{BoxedSink, MediaTransportKind};
use bytes::{Bytes, BytesMut};
use citadel_media::wire::encode_control;
use citadel_media::{
    ControlMessage, FrameFlags, FrameHeader, MediaConfig, MediaFrame, MediaStats,
    MediaTrackDescriptor, Packetizer, SendQueue, TrackId, TrackKind,
};
use citadel_proto::prelude::NetworkError;

/// Outbound half of a media endpoint. `send_frame` is synchronous and never
/// blocks; control messages (`announce`, `end_of_stream`) are async.
pub struct MediaSender {
    kind: MediaTransportKind,
    media: BoxedSink,
    control: BoxedSink,
    packetizer: Packetizer,
    queue: SendQueue,
    scratch: BytesMut,
    stats: MediaStats,
}

impl std::fmt::Debug for MediaSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaSender")
            .field("kind", &self.kind)
            .field("queued", &self.queue.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl MediaSender {
    pub(crate) fn new(
        kind: MediaTransportKind,
        media: BoxedSink,
        control: BoxedSink,
        config: MediaConfig,
        send_queue_frames: usize,
    ) -> Result<Self, NetworkError> {
        Ok(Self {
            kind,
            media,
            control,
            packetizer: Packetizer::new(config).net()?,
            queue: SendQueue::new(send_queue_frames).net()?,
            scratch: BytesMut::with_capacity(config.max_fragment_payload * 2),
            stats: MediaStats::new(),
        })
    }

    pub fn kind(&self) -> MediaTransportKind {
        self.kind
    }

    pub fn stats(&self) -> MediaStats {
        self.stats
    }

    /// Tells the peer which tracks this side will send.
    pub async fn announce(&mut self, tracks: &[MediaTrackDescriptor]) -> Result<(), NetworkError> {
        self.send_control(&ControlMessage::AnnounceTracks(tracks.to_vec()))
    }

    /// Acknowledges a peer's announcement.
    pub async fn accept(&mut self, tracks: &[MediaTrackDescriptor]) -> Result<(), NetworkError> {
        self.send_control(&ControlMessage::AcceptTracks(tracks.to_vec()))
    }

    /// Marks `track` finished on the peer side, telling it how many frames
    /// (`0..frames_sent`) were sent so it can drain in-flight media that races
    /// this control message. Fails fast if frames are still parked in the send
    /// queue after a drain attempt (a stale count would lie to the peer).
    pub async fn end_of_stream(&mut self, track: TrackId) -> Result<(), NetworkError> {
        self.drain()?;
        if !self.queue.is_empty() {
            return Err(citadel_io::error!(
                citadel_io::ErrorCode::MediaTransportClosed,
                "cannot end stream: unsent frames remain in the send queue"
            ));
        }
        let frames_sent = self.packetizer.next_sequence(track);
        self.send_control(&ControlMessage::EndOfStream { track, frames_sent })
    }

    /// Queues a frame and drains the queue to the transport. Returns how many
    /// frames the queue's drop policy evicted to make room (0 normally).
    ///
    /// Sequence numbers are assigned at packetization, so evicted frames never
    /// consume one. If the transport rejects a datagram the frame stays at the
    /// head of the queue (retried on the next call) and the error is returned.
    pub fn send_frame(
        &mut self,
        track: TrackId,
        kind: TrackKind,
        timestamp: u32,
        flags: FrameFlags,
        payload: Bytes,
    ) -> Result<usize, NetworkError> {
        let frame = MediaFrame {
            header: FrameHeader {
                track,
                kind,
                // Placeholder: the packetizer assigns the real sequence on drain.
                sequence: 0,
                timestamp,
                flags,
            },
            payload,
        };
        let dropped = usize::from(self.queue.push(frame).is_some());
        self.stats.frames_dropped_on_send += dropped as u64;
        self.drain()?;
        Ok(dropped)
    }

    fn drain(&mut self) -> Result<(), NetworkError> {
        loop {
            let Some(frame) = self.queue.iter().next().cloned() else {
                return Ok(());
            };
            self.send_one(&frame)?;
            drop(self.queue.pop());
        }
    }

    fn send_one(&mut self, frame: &MediaFrame) -> Result<(), NetworkError> {
        let h = frame.header;
        let fragments = self
            .packetizer
            .packetize(h.track, h.kind, h.timestamp, h.flags, frame.payload.clone())
            .net()?;
        for fragment in fragments {
            let len = fragment.wire_len();
            self.scratch.reserve(len);
            fragment.write_into(&mut self.scratch);
            self.media.send_datagram(self.scratch.split())?;
            self.stats.fragments_sent += 1;
            self.stats.bytes_sent += len as u64;
        }
        self.stats.frames_sent += 1;
        Ok(())
    }

    fn send_control(&mut self, msg: &ControlMessage) -> Result<(), NetworkError> {
        let body = msg.encode().net()?;
        self.control
            .send_datagram(BytesMut::from(encode_control(&body).as_slice()))
    }
}
