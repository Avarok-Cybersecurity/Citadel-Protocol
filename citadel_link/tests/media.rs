//! The media loss metadata a true close carries (owner decision, §14): one record per stream,
//! with correct counts, and no payload bytes.

use citadel_link::event::{CloseReason, CloseSummary, ShutdownReason};
use citadel_link::outbox::{
    FramePoint, LinkDisconnect, LinkOutbox, LossyCounts, MediaLedger, MediaStream, Payload,
};
use citadel_link::{ConnectionId, LinkKind, RouteKind};
use citadel_media::frame::{TrackId, TrackKind};
use citadel_negotiation::settings::MediaTransportKind;

struct Bytes(Vec<u8>);

impl Payload for Bytes {
    fn byte_len(&self) -> usize {
        self.0.len()
    }
    fn wipe(&mut self) {
        self.0.fill(0);
    }
}

fn frame(sequence: u32) -> FramePoint {
    FramePoint {
        sequence,
        timestamp: sequence.wrapping_mul(960),
    }
}

fn stream(track: u8, kind: TrackKind) -> MediaStream {
    MediaStream {
        track: TrackId(track),
        kind,
        codec: *b"OPUS",
        lane: MediaTransportKind::Unreliable,
    }
}

#[test]
fn a_close_with_frames_queued_yields_one_loss_record_per_stream_with_correct_counts() {
    let mut ledger = MediaLedger::empty();
    ledger.open(stream(0, TrackKind::Audio));
    ledger.open(stream(1, TrackKind::Video));
    ledger.rode(RouteKind::Direct);
    for seq in 1..=10 {
        assert!(ledger.handed(TrackId(0), frame(seq)));
        assert!(ledger.handed(TrackId(1), frame(seq)));
    }
    assert!(
        !ledger.handed(TrackId(9), frame(1)),
        "an unopened track is refused"
    );
    ledger.confirmed(TrackId(0), frame(4));
    ledger.confirmed(TrackId(1), frame(6));
    ledger.dropped(TrackId(1), 8);
    let summary = CloseSummary {
        link: LinkKind::Peer {
            local_cid: 1,
            peer_cid: 2,
        },
        connection: ConnectionId(1),
        reason: CloseReason::Local(ShutdownReason::Shutdown),
        incarnations: 1,
    };
    let drained = LinkOutbox::<Bytes>::new(10, true).drain();
    let lossy = LossyCounts {
        udp_datagrams: 3,
        control_frames: 1,
    };
    let event = LinkDisconnect::assemble(summary, drained, vec![], &mut ledger, vec![], lossy);
    assert_eq!(event.media.len(), 2, "exactly one record per stream");
    let audio = event.media[0];
    assert_eq!(audio.stream.kind, TrackKind::Audio);
    assert_eq!(
        (audio.last_confirmed, audio.last_handed),
        (Some(frame(4)), Some(frame(10)))
    );
    assert_eq!(audio.dropped, 6);
    assert_eq!(audio.dropped_span, Some((5 * 960, 10 * 960)));
    assert!(!audio.needs_resync);
    assert_eq!(audio.route, Some(RouteKind::Direct));
    let video = event.media[1];
    assert_eq!(
        video.dropped, 4,
        "frame 8 dropped by the queue, 7, 9 and 10 still queued"
    );
    assert_eq!(video.dropped_span, Some((8 * 960, 10 * 960)));
    assert!(
        video.needs_resync,
        "video lost a frame after its last confirmed one"
    );
    assert_eq!(
        event.dropped.media_frames, 10,
        "the ledger is the one source of the count"
    );
    assert_eq!(
        (event.dropped.udp_datagrams, event.dropped.control_frames),
        (3, 1)
    );
    assert!(ledger.close().is_empty(), "the close took the ledger");
}

#[test]
fn confirmation_follows_wrapping_sequence_numbers() {
    let mut ledger = MediaLedger::empty();
    ledger.open(stream(0, TrackKind::Audio));
    for seq in [u32::MAX - 1, u32::MAX, 0, 1] {
        ledger.handed(TrackId(0), frame(seq));
    }
    ledger.confirmed(TrackId(0), frame(0));
    let loss = ledger.close();
    assert_eq!(loss[0].dropped, 1, "only frame 1 was still in flight");
}
