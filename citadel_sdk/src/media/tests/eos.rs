//! End-of-stream ordering tests: EOS carries `frames_sent`, so it must not
//! outrace in-flight media; a lost tail resolves via Gap after the deadline.
use super::{payload, run, source, CFG};
use crate::media::endpoint::MediaEndpoint;
use crate::media::receiver::MediaEvent;
use crate::media::sender::MediaSender;
use crate::media::transport::{MediaDatagramSink, MediaTransportKind, ReliableSink};
use bytes::BytesMut;
use citadel_io::time::Instant;
use citadel_media::{FrameFlags, TrackId, TrackKind};

/// Captures the datagrams of `n` frames plus the end-of-stream control
/// message, so tests can replay them in adversarial orders.
async fn captured_stream(n: u32) -> (Vec<BytesMut>, BytesMut) {
    let (media_sink, mut media_rx) = ReliableSink::pair();
    let (ctl_sink, mut ctl_rx) = ReliableSink::pair();
    let mut sender = MediaSender::new(
        MediaTransportKind::Unreliable,
        Box::new(media_sink),
        Box::new(ctl_sink),
        CFG.media,
        CFG.send_queue_frames,
    )
    .unwrap();
    for i in 0..n {
        let dropped = sender
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
    sender.end_of_stream(TrackId(0)).await.unwrap();
    let mut frames = Vec::new();
    while let Ok(d) = media_rx.try_recv() {
        frames.push(d);
    }
    (frames, ctl_rx.try_recv().unwrap())
}

fn replay_endpoint() -> (ReliableSink, ReliableSink, crate::media::MediaReceiver) {
    let (ctl_sink, ctl_rx) = ReliableSink::pair();
    let (m_sink, m_rx) = ReliableSink::pair();
    let (_tx, rx) = MediaEndpoint::assemble(
        MediaTransportKind::Unreliable,
        Box::new(m_sink.clone()),
        Box::new(ctl_sink.clone()),
        source(m_rx),
        Some(source(ctl_rx)),
        CFG,
        Instant::now(),
    )
    .unwrap()
    .split();
    (m_sink, ctl_sink, rx)
}

#[test]
fn eos_outracing_media_frames_is_held_until_all_frames_arrive() {
    run(async {
        let (frames, eos) = captured_stream(3).await;
        let (mut m_sink, mut ctl_sink, mut rx) = replay_endpoint();
        // EOS wins the race: it lands before any media fragment.
        ctl_sink.send_datagram(eos).unwrap();
        for frame in frames {
            m_sink.send_datagram(frame).unwrap();
        }
        drop((m_sink, ctl_sink));
        for i in 0..3u32 {
            assert!(
                matches!(rx.next_event().await, MediaEvent::Frame(f) if f.header.sequence == i)
            );
        }
        assert_eq!(rx.next_event().await, MediaEvent::EndOfStream(TrackId(0)));
        assert_eq!(rx.next_event().await, MediaEvent::Closed);
        assert_eq!(rx.stats().frames_missing, 0);
    })
}

#[test]
fn eos_with_lost_tail_emits_gap_then_eos_after_deadline() {
    run(async {
        let (frames, eos) = captured_stream(3).await;
        let (mut m_sink, mut ctl_sink, mut rx) = replay_endpoint();
        // Frame 2 is genuinely lost; the lanes stay open so the EOS deadline
        // (not transport closure) is what resolves the record.
        m_sink.send_datagram(frames[0].clone()).unwrap();
        m_sink.send_datagram(frames[1].clone()).unwrap();
        ctl_sink.send_datagram(eos).unwrap();
        assert!(matches!(rx.next_event().await, MediaEvent::Frame(f) if f.header.sequence == 0));
        assert!(matches!(rx.next_event().await, MediaEvent::Frame(f) if f.header.sequence == 1));
        assert_eq!(
            rx.next_event().await,
            MediaEvent::Gap {
                track: TrackId(0),
                missing_from: 2,
                missing_to: 2
            }
        );
        assert_eq!(rx.next_event().await, MediaEvent::EndOfStream(TrackId(0)));
        assert_eq!(rx.stats().frames_missing, 1);
        drop((m_sink, ctl_sink));
        assert_eq!(rx.next_event().await, MediaEvent::Closed);
    })
}
