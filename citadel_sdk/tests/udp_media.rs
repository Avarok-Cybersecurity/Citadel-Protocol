//! End-to-end media streaming over the UDP subsystem: two peers connect through a test server,
//! stream the real fixture files (WAV audio / IVF-VP8 video) via `citadel_sdk::media`, and assert
//! byte-exact, in-order, loss-free delivery — plus the reliable fallback when UDP is disabled.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::fixtures::{ensure_bytes, Fixture};
    use crate::common::media::*;
    use bytes::Bytes;
    use citadel_io::tokio;
    use citadel_sdk::citadel_media::demux::{vp8_is_keyframe, IvfWriter};
    use citadel_sdk::citadel_media::descriptor::MediaTrackDescriptor;
    use citadel_sdk::citadel_media::frame::{FrameFlags, TrackId, TrackKind};
    use citadel_sdk::media::{MediaEndpoint, MediaEvent, MediaTransportConfig, MediaTransportKind};
    use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers, TestBarrier};
    use futures::stream::FuturesUnordered;
    use futures::TryStreamExt;
    use rstest::rstest;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use uuid::Uuid;

    const TRACK: TrackId = TrackId(0);

    /// Streamed payloads plus per-frame flags, shared by sender and assertion.
    #[derive(Clone)]
    struct Stream {
        kind: TrackKind,
        descriptor: MediaTrackDescriptor,
        frames: Vec<(u32, FrameFlags, Bytes)>,
    }

    async fn run_stream_pair(udp_mode: UdpMode, expected_kind: MediaTransportKind, stream: Stream) {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info::<StackedRatchet>();
        let uuids = [Uuid::new_v4(), Uuid::new_v4()];
        let kernels = FuturesUnordered::new();

        for idx in 0..2 {
            let other = uuids[1 - idx];
            let is_sender = idx == 0;
            let stream = stream.clone();
            let agg = PeerConnectionSetupAggregator::default()
                .with_peer_custom(other)
                .ensure_registered()
                .with_udp_mode(udp_mode)
                .add();
            let settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuids[idx])
                    .build()
                    .unwrap();
            let kernel =
                PeerConnectionKernel::new(settings, agg, move |mut results, remote| async move {
                    let conn = results.recv().await.unwrap().unwrap();
                    let cfg: MediaTransportConfig = test_media_config();
                    let (endpoint, _peer_remote) = MediaEndpoint::from_peer_connection(conn, cfg)
                        .await
                        .unwrap();
                    assert_eq!(endpoint.kind(), expected_kind);
                    let (mut tx, mut rx) = endpoint.split();
                    wait_for_peers().await;

                    if is_sender {
                        tx.announce(std::slice::from_ref(&stream.descriptor))
                            .await
                            .unwrap();
                        for (i, (ts, flags, payload)) in stream.frames.iter().enumerate() {
                            let dropped = tx
                                .send_frame(TRACK, stream.kind, *ts, *flags, payload.clone())
                                .unwrap();
                            assert_eq!(dropped, 0, "loopback send must not evict");
                            // Light pacing: real capture is paced (20 ms/frame);
                            // an unpaced 160-datagram burst overflows the UDP
                            // socket buffer on loopback and loses the tail.
                            if i % 4 == 3 {
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                        }
                        tx.end_of_stream(TRACK).await.unwrap();
                    } else {
                        let mut got: Vec<(u32, FrameFlags, Bytes)> = Vec::new();
                        let mut tracks: Vec<MediaTrackDescriptor> = Vec::new();
                        loop {
                            match rx.next_event().await {
                                MediaEvent::Tracks(t) => tracks = t,
                                MediaEvent::Frame(frame) => {
                                    assert_eq!(frame.header.track, TRACK);
                                    assert_eq!(frame.header.kind, stream.kind);
                                    got.push((
                                        frame.header.timestamp,
                                        frame.header.flags,
                                        frame.payload,
                                    ));
                                }
                                MediaEvent::Gap {
                                    missing_from,
                                    missing_to,
                                    ..
                                } => {
                                    panic!("loss on loopback: frames {missing_from}..={missing_to}")
                                }
                                MediaEvent::EndOfStream(track) => {
                                    assert_eq!(track, TRACK);
                                    break;
                                }
                                MediaEvent::Closed => panic!("closed before end of stream"),
                            }
                        }
                        assert_eq!(tracks, vec![stream.descriptor.clone()]);
                        assert_eq!(got.len(), stream.frames.len(), "frame count");
                        for ((ts, flags, payload), (ets, eflags, epayload)) in
                            got.iter().zip(stream.frames.iter())
                        {
                            assert_eq!(ts, ets);
                            assert_eq!(flags, eflags);
                            assert_eq!(payload, epayload);
                        }
                        let sent = sha_of_parts(stream.frames.iter().map(|(_, _, p)| p.as_ref()));
                        let received = sha_of_parts(got.iter().map(|(_, _, p)| p.as_ref()));
                        assert_eq!(sent, received, "byte-exact reassembly");
                        assert_eq!(rx.stats().frames_missing, 0);
                        assert_eq!(rx.stats().gaps_skipped, 0);
                    }

                    // Rendezvous before dropping the halves so DisconnectUDP only
                    // ever tears down an idle subsystem.
                    wait_for_peers().await;
                    client_success.fetch_add(1, Ordering::Relaxed);
                    remote.shutdown_kernel().await
                });
            let client = DefaultNodeBuilder::default().build(kernel).unwrap();
            kernels.push(async move { client.await.map(|_| ()) });
        }

        let clients = Box::pin(async move { kernels.try_collect::<()>().await.map(|_| ()) });
        let result = citadel_io::tokio::time::timeout(
            Duration::from_secs(120),
            futures::future::try_select(server, clients),
        )
        .await;
        assert!(result.expect("test timed out").is_ok());
        assert_eq!(client_success.load(Ordering::Relaxed), 2);
    }

    fn audio_stream(bytes: &[u8]) -> Stream {
        let (sample_rate, chunks) = wav_chunks(bytes);
        let samples_per_chunk = (sample_rate as u64 * AUDIO_FRAME_MICROS / 1_000_000) as u32;
        let frames = chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| (i as u32 * samples_per_chunk, FrameFlags::KEYFRAME, chunk))
            .collect();
        Stream {
            kind: TrackKind::Audio,
            descriptor: MediaTrackDescriptor {
                track: TRACK,
                kind: TrackKind::Audio,
                clock_rate: sample_rate,
                codec: *b"PCM\0",
                channels: 2,
                width: 0,
                height: 0,
                name: "audio".into(),
            },
            frames,
        }
    }

    #[rstest]
    #[case(UdpMode::Enabled, MediaTransportKind::Unreliable)]
    #[case(UdpMode::Disabled, MediaTransportKind::Reliable)]
    #[timeout(Duration::from_secs(150))]
    #[tokio::test(flavor = "multi_thread")]
    async fn p2p_audio_stream(
        #[case] udp_mode: UdpMode,
        #[case] expected_kind: MediaTransportKind,
    ) {
        let Some(bytes) = ensure_bytes(Fixture::Wav).unwrap() else {
            return; // offline; loudly reported by the fixture helper
        };
        run_stream_pair(udp_mode, expected_kind, audio_stream(&bytes)).await;
    }

    #[rstest]
    #[timeout(Duration::from_secs(150))]
    #[tokio::test(flavor = "multi_thread")]
    async fn p2p_udp_video_ivf_stream() {
        let Some(bytes) = ensure_bytes(Fixture::Vp8Ivf).unwrap() else {
            return;
        };
        let (header, ivf) = ivf_frames(&bytes);
        assert!(ivf.len() > 1, "fixture must contain multiple frames");
        assert!(
            ivf.iter().any(|(_, data)| data.len() > 2 * 1100),
            "fixture frames must exercise fragmentation"
        );
        let frames: Vec<(u32, FrameFlags, Bytes)> = ivf
            .iter()
            .map(|(pts, data)| {
                let flags = if vp8_is_keyframe(data) {
                    FrameFlags::KEYFRAME
                } else {
                    FrameFlags::NONE
                };
                (*pts as u32, flags, data.clone())
            })
            .collect();
        let stream = Stream {
            kind: TrackKind::Video,
            descriptor: MediaTrackDescriptor {
                track: TRACK,
                kind: TrackKind::Video,
                clock_rate: header.timebase_den,
                codec: header.fourcc,
                channels: 0,
                width: header.width,
                height: header.height,
                name: "video".into(),
            },
            frames: frames.clone(),
        };
        run_stream_pair(UdpMode::Enabled, MediaTransportKind::Unreliable, stream).await;

        // The received frames are asserted byte-equal above; prove the remux path reproduces a
        // parseable IVF byte-for-byte from those frames.
        let mut writer = IvfWriter::new(Vec::new(), &header).unwrap();
        for (pts, data) in &ivf {
            writer.write_frame(*pts, data).unwrap();
        }
        let remuxed = writer.finish().unwrap();
        let (header2, ivf2) = ivf_frames(&remuxed);
        assert_eq!(header, header2);
        assert_eq!(ivf, ivf2);
    }
}
