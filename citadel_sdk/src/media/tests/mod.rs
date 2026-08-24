//! Sender/receiver/demux tests over an in-process datagram pair (harness +
//! roundtrip coverage; drop-policy/gap/config cases live in `policy`).
//!
//! The only test double is the in-memory `BytesMut` channel: `ReliableSink`
//! (production) feeds an `UnboundedReceiver` that a thin adapter exposes as a
//! `MediaDatagramSource`. This exercises packetization, queue policy,
//! reassembly, jitter ordering and control demux end-to-end without a
//! network; the proto channel halves are covered by the integration tests.
use super::config::{
    MediaTransportConfig, RECOMMENDED_FRAGMENT_PAYLOAD, RECOMMENDED_UDP_PAYLOAD_BUDGET,
};
use super::endpoint::MediaEndpoint;
use super::receiver::{MediaEvent, MediaReceiver};
use super::sender::MediaSender;
use super::transport::{BoxedSource, MediaTransportKind, ReliableSink};
use bytes::{Bytes, BytesMut};
use citadel_io::time::{Duration, Instant};
use citadel_io::tokio::sync::mpsc::UnboundedReceiver;
use citadel_media::{FrameFlags, MediaConfig, MediaTrackDescriptor, TrackId, TrackKind};
use citadel_proto::prelude::SecBuffer;
use futures::StreamExt;

// Test baseline (PCND: production callers construct explicitly).
pub(super) const CFG: MediaTransportConfig = MediaTransportConfig {
    media: MediaConfig {
        max_fragment_payload: RECOMMENDED_FRAGMENT_PAYLOAD,
        max_frame_bytes: 1 << 20,
        max_reorder_window: 64,
        jitter_depth_micros: 20_000,
        max_pending_frames: 32,
    },
    send_queue_frames: 2,
    udp_payload_budget: RECOMMENDED_UDP_PAYLOAD_BUDGET,
    udp_wait: Duration::from_millis(10),
};

pub(super) fn run<F: std::future::Future<Output = ()>>(f: F) {
    citadel_io::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

pub(super) fn source(rx: UnboundedReceiver<BytesMut>) -> BoxedSource {
    Box::pin(
        citadel_io::tokio_stream::wrappers::UnboundedReceiverStream::new(rx).map(SecBuffer::from),
    )
}

/// Builds a full-duplex in-memory endpoint. `Unreliable` uses two lanes
/// (media + control), `Reliable` a single shared lane.
pub(super) fn endpoint(kind: MediaTransportKind) -> (MediaSender, MediaReceiver) {
    let (ctl_sink, ctl_rx) = ReliableSink::pair();
    let (media_sink, media_src, ctl_src) = match kind {
        MediaTransportKind::Unreliable => {
            let (m_sink, m_rx) = ReliableSink::pair();
            (m_sink, source(m_rx), Some(source(ctl_rx)))
        }
        MediaTransportKind::Reliable => (ctl_sink.clone(), source(ctl_rx), None),
    };
    MediaEndpoint::assemble(
        kind,
        Box::new(media_sink),
        Box::new(ctl_sink),
        media_src,
        ctl_src,
        CFG,
        Instant::now(),
    )
    .unwrap()
    .split()
}

pub(super) fn descriptor() -> MediaTrackDescriptor {
    MediaTrackDescriptor {
        track: TrackId(0),
        kind: TrackKind::Audio,
        clock_rate: 48_000,
        codec: *b"opus",
        channels: 2,
        width: 0,
        height: 0,
        name: "mic".into(),
    }
}

pub(super) fn payload(i: usize) -> Bytes {
    Bytes::from(vec![
        i as u8;
        if i == 3 {
            3 * RECOMMENDED_FRAGMENT_PAYLOAD + 7
        } else {
            160
        }
    ])
}

async fn roundtrip(kind: MediaTransportKind, n: usize) {
    let (mut tx, mut rx) = endpoint(kind);
    assert_eq!(tx.kind(), kind);
    tx.announce(&[descriptor()]).await.unwrap();
    for i in 0..n {
        let dropped = tx
            .send_frame(
                TrackId(0),
                TrackKind::Audio,
                i as u32 * 960,
                FrameFlags::NONE,
                payload(i),
            )
            .unwrap();
        assert_eq!(dropped, 0);
    }
    tx.end_of_stream(TrackId(0)).await.unwrap();
    drop(tx);

    // Control and media lanes are independent in unreliable mode, so only the
    // relative order of frames is guaranteed; in reliable mode everything is
    // strictly ordered on one lane.
    let mut events = Vec::new();
    loop {
        match rx.next_event().await {
            MediaEvent::Closed => break,
            e => events.push(e),
        }
    }
    assert_eq!(rx.next_event().await, MediaEvent::Closed);
    let frames: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            MediaEvent::Frame(f) => Some(f),
            _ => None,
        })
        .collect();
    assert_eq!(frames.len(), n);
    for (i, f) in frames.iter().enumerate() {
        assert_eq!(f.header.sequence, i as u32);
        assert_eq!(f.header.timestamp, i as u32 * 960);
        assert_eq!(f.payload, payload(i));
    }
    assert!(events.contains(&MediaEvent::Tracks(vec![descriptor()])));
    // The EOS control message carries frames_sent, so even when it races the
    // media lane the receiver holds it until every frame has been delivered.
    assert_eq!(events.last(), Some(&MediaEvent::EndOfStream(TrackId(0))));
    if kind == MediaTransportKind::Reliable {
        assert!(matches!(events.first(), Some(MediaEvent::Tracks(_))));
    }
    let s = rx.stats();
    assert_eq!(s.frames_delivered as usize, n);
    assert_eq!(s.fragments_rejected, 0);
    assert_eq!(s.gaps_skipped, 0);
}

#[test]
fn unreliable_roundtrip_with_multi_fragment_frame() {
    run(async {
        roundtrip(MediaTransportKind::Unreliable, 8).await;
    })
}

#[test]
fn reliable_mode_demuxes_control_and_fragments_on_one_stream() {
    run(async {
        roundtrip(MediaTransportKind::Reliable, 8).await;
    })
}

#[test]
fn closing_media_lane_reports_closed_once_drained() {
    run(async {
        let (mut tx, mut rx) = endpoint(MediaTransportKind::Unreliable);
        let dropped = tx
            .send_frame(
                TrackId(1),
                TrackKind::Video,
                0,
                FrameFlags::KEYFRAME,
                payload(0),
            )
            .unwrap();
        assert_eq!(dropped, 0);
        drop(tx);
        assert!(
            matches!(rx.next_event().await, MediaEvent::Frame(f) if f.header.flags.is_keyframe())
        );
        assert_eq!(rx.next_event().await, MediaEvent::Closed);
    })
}

mod eos;
mod policy;
