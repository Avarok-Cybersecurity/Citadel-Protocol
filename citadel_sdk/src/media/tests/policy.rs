//! Drop-policy, loss/gap, and config-negative tests.
use super::{endpoint, payload, run, source, CFG};
use crate::media::config::{
    MediaTransportConfig, RECOMMENDED_FRAGMENT_PAYLOAD, RECOMMENDED_UDP_PAYLOAD_BUDGET,
};
use crate::media::endpoint::MediaEndpoint;
use crate::media::receiver::MediaEvent;
use crate::media::sender::MediaSender;
use crate::media::transport::{MediaDatagramSink, MediaTransportKind, ReliableSink};
use bytes::{Bytes, BytesMut};
use citadel_io::time::Instant;
use citadel_io::ErrorCode;
use citadel_media::{FrameFlags, MediaConfig, TrackId, TrackKind};
use citadel_proto::prelude::NetworkError;

/// Fails the first `failures` datagrams, then accepts. Only way to make the
/// queue retain frames deterministically (production sinks never recover).
struct FlakySink {
    failures: usize,
    inner: ReliableSink,
}

impl MediaDatagramSink for FlakySink {
    fn send_datagram(&mut self, buf: BytesMut) -> Result<(), NetworkError> {
        if self.failures > 0 {
            self.failures -= 1;
            return Err(citadel_io::error!(ErrorCode::MediaTransportClosed, "flaky"));
        }
        self.inner.send_datagram(buf)
    }
}

#[test]
fn queue_drop_policy_reports_evictions() {
    run(async {
        let (ctl_sink, ctl_rx) = ReliableSink::pair();
        let (m_sink, m_rx) = ReliableSink::pair();
        let (mut tx, mut rx) = MediaEndpoint::assemble(
            MediaTransportKind::Unreliable,
            Box::new(FlakySink {
                failures: 2,
                inner: m_sink,
            }),
            Box::new(ctl_sink),
            source(m_rx),
            Some(source(ctl_rx)),
            CFG,
            Instant::now(),
        )
        .unwrap()
        .split();
        let send = |tx: &mut MediaSender, i: u32, flags| {
            tx.send_frame(TrackId(0), TrackKind::Video, i, flags, payload(0))
        };
        // Two failures keep frame 0 at the head; queue capacity is 2.
        assert_eq!(
            send(&mut tx, 0, FrameFlags::KEYFRAME).unwrap_err().code(),
            ErrorCode::MediaTransportClosed
        );
        assert_eq!(
            send(&mut tx, 1, FrameFlags::DISCARDABLE)
                .unwrap_err()
                .code(),
            ErrorCode::MediaTransportClosed
        );
        // Third push evicts the discardable frame (ts=1), then the drain succeeds.
        assert_eq!(send(&mut tx, 2, FrameFlags::NONE).unwrap(), 1);
        assert_eq!(tx.stats().frames_dropped_on_send, 1);
        assert_eq!(tx.stats().frames_sent, 2);
        drop(tx);
        let mut timestamps = Vec::new();
        while let MediaEvent::Frame(f) = rx.next_event().await {
            timestamps.push(f.header.timestamp);
        }
        // The two failed attempts burned sequences 0 and 1 (documented).
        assert_eq!(timestamps, vec![0, 2]);
    })
}

#[test]
fn out_of_order_delivery_and_gap_after_jitter_depth() {
    run(async {
        let (ctl_sink, ctl_rx) = ReliableSink::pair();
        let (m_sink, m_rx) = ReliableSink::pair();
        let (tx, mut rx) = MediaEndpoint::assemble(
            MediaTransportKind::Unreliable,
            Box::new(m_sink.clone()),
            Box::new(ctl_sink),
            source(m_rx),
            Some(source(ctl_rx)),
            CFG,
            Instant::now(),
        )
        .unwrap()
        .split();
        // Capture datagrams, then replay 0, 2 (1 lost).
        let (cap_sink, mut cap_rx) = ReliableSink::pair();
        let mut capture = MediaSender::new(
            MediaTransportKind::Unreliable,
            Box::new(cap_sink),
            Box::new(ReliableSink::pair().0),
            CFG.media,
            CFG.send_queue_frames,
        )
        .unwrap();
        for i in 0..3u32 {
            let dropped = capture
                .send_frame(
                    TrackId(0),
                    TrackKind::Audio,
                    i,
                    FrameFlags::NONE,
                    payload(0),
                )
                .unwrap();
            assert_eq!(dropped, 0);
        }
        let mut datagrams = Vec::new();
        while let Ok(d) = cap_rx.try_recv() {
            datagrams.push(d);
        }
        let mut m_sink = m_sink;
        m_sink.send_datagram(datagrams[0].clone()).unwrap();
        m_sink.send_datagram(datagrams[2].clone()).unwrap();
        drop((tx, m_sink));
        assert!(matches!(rx.next_event().await, MediaEvent::Frame(f) if f.header.sequence == 0));
        assert_eq!(
            rx.next_event().await,
            MediaEvent::Gap {
                track: TrackId(0),
                missing_from: 1,
                missing_to: 1
            }
        );
        assert!(matches!(rx.next_event().await, MediaEvent::Frame(f) if f.header.sequence == 2));
        assert_eq!(rx.next_event().await, MediaEvent::Closed);
        assert_eq!(rx.stats().frames_missing, 1);
    })
}

#[test]
fn config_validation_negatives() {
    assert!(CFG.validate().is_ok());
    let too_big = MediaTransportConfig {
        media: MediaConfig {
            max_fragment_payload: RECOMMENDED_UDP_PAYLOAD_BUDGET,
            ..CFG.media
        },
        ..CFG
    };
    assert_eq!(
        too_big.validate().unwrap_err().code(),
        ErrorCode::MediaConfigInvalid
    );
    let no_queue = MediaTransportConfig {
        send_queue_frames: 0,
        ..CFG
    };
    assert_eq!(
        no_queue.validate().unwrap_err().code(),
        ErrorCode::MediaConfigInvalid
    );
    let bad_media = MediaTransportConfig {
        media: MediaConfig {
            jitter_depth_micros: 0,
            ..CFG.media
        },
        ..CFG
    };
    assert_eq!(
        bad_media.validate().unwrap_err().code(),
        ErrorCode::MediaConfigInvalid
    );
    assert_eq!(CFG.max_datagram_len(), RECOMMENDED_FRAGMENT_PAYLOAD + 20);
}

#[test]
fn oversized_frame_maps_to_frame_rejected() {
    let (mut tx, _rx) = endpoint(MediaTransportKind::Reliable);
    let err = tx
        .send_frame(
            TrackId(0),
            TrackKind::Video,
            0,
            FrameFlags::NONE,
            Bytes::from(vec![0u8; (1 << 20) + 1]),
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::MediaFrameRejected);
}
