//! The UDP media tests assert a guarantee the Unreliable transport does not make.
//!
//! `udp_media.rs` / `udp_media_modes.rs` panic on any `MediaEvent::Gap` and require
//! every frame to arrive, and keep that true only by pacing the sender with 1 ms
//! sleeps every four frames. Any hiccup that lets datagrams bunch up — a capture
//! pipeline flushing after a stall, a receiver descheduled under load — overflows
//! the loopback socket buffer or lets the reliable `EndOfStream` outrun the UDP tail
//! by more than the jitter depth, and the receiver correctly reports a `Gap`.
//!
//! This test is the stock `udp_media.rs` assertion with the pacing crutch removed:
//! the sender emits its frames as one burst, which is a legal use of the API
//! (`send_frame` never blocks and reports zero evictions). It fails on master
//! because the assertion, not the transport, is wrong.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::fixtures::{ensure_bytes, Fixture};
    use crate::common::media::*;
    use bytes::Bytes;
    use citadel_io::tokio;
    use citadel_sdk::citadel_media::descriptor::MediaTrackDescriptor;
    use citadel_sdk::citadel_media::frame::{FrameFlags, TrackId, TrackKind};
    use citadel_sdk::media::{MediaEndpoint, MediaEvent, MediaTransportKind};
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

    #[rstest]
    #[timeout(Duration::from_secs(150))]
    #[tokio::test(flavor = "multi_thread")]
    async fn p2p_udp_audio_burst_asserted_lossless() {
        citadel_logging::setup_log();
        let Some(bytes) = ensure_bytes(Fixture::Wav).unwrap() else {
            return;
        };
        let (sample_rate, chunks) = wav_chunks(&bytes);
        let samples = (sample_rate as u64 * AUDIO_FRAME_MICROS / 1_000_000) as u32;
        let frames: Vec<(u32, Bytes)> = chunks
            .into_iter()
            .enumerate()
            .map(|(i, c)| (i as u32 * samples, c))
            .collect();
        let descriptor = MediaTrackDescriptor {
            track: TRACK,
            kind: TrackKind::Audio,
            clock_rate: sample_rate,
            codec: *b"PCM\0",
            channels: 2,
            width: 0,
            height: 0,
            name: "audio".into(),
        };

        TestBarrier::setup(2);
        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info::<StackedRatchet>();
        let uuids = [Uuid::new_v4(), Uuid::new_v4()];
        let kernels = FuturesUnordered::new();

        for idx in 0..2 {
            let is_sender = idx == 0;
            let frames = frames.clone();
            let descriptor = descriptor.clone();
            let agg = PeerConnectionSetupAggregator::default()
                .with_peer_custom(uuids[1 - idx])
                .ensure_registered()
                .with_udp_mode(UdpMode::Enabled)
                .add();
            let settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuids[idx])
                    .build()
                    .unwrap();
            let kernel =
                PeerConnectionKernel::new(settings, agg, move |mut results, remote| async move {
                    let conn = results.recv().await.unwrap().unwrap();
                    let (endpoint, _peer_remote) =
                        MediaEndpoint::from_peer_connection(conn, test_media_config())
                            .await
                            .unwrap();
                    assert_eq!(endpoint.kind(), MediaTransportKind::Unreliable);
                    let (mut tx, mut rx) = endpoint.split();
                    wait_for_peers().await;

                    if is_sender {
                        tx.announce(std::slice::from_ref(&descriptor))
                            .await
                            .unwrap();
                        for (ts, payload) in &frames {
                            let dropped = tx
                                .send_frame(
                                    TRACK,
                                    TrackKind::Audio,
                                    *ts,
                                    FrameFlags::KEYFRAME,
                                    payload.clone(),
                                )
                                .unwrap();
                            assert_eq!(dropped, 0, "send_frame accepted the burst");
                        }
                        tx.end_of_stream(TRACK).await.unwrap();
                    } else {
                        let mut got: Vec<(u32, Bytes)> = Vec::new();
                        loop {
                            match rx.next_event().await {
                                MediaEvent::Tracks(t) => assert_eq!(t, vec![descriptor.clone()]),
                                MediaEvent::Frame(frame) => {
                                    got.push((frame.header.timestamp, frame.payload))
                                }
                                // The stock assertion under test (udp_media.rs:104-110).
                                MediaEvent::Gap {
                                    missing_from,
                                    missing_to,
                                    ..
                                } => panic!(
                                    "loss on loopback: frames {missing_from}..={missing_to}; {:?}",
                                    rx.stats()
                                ),
                                MediaEvent::EndOfStream(track) => {
                                    assert_eq!(track, TRACK);
                                    break;
                                }
                                MediaEvent::Closed => panic!("closed before end of stream"),
                            }
                        }
                        assert_eq!(got, frames, "every frame, in order, byte-exact");
                        assert_eq!(rx.stats().frames_missing, 0);
                    }

                    wait_for_peers().await;
                    client_success.fetch_add(1, Ordering::Relaxed);
                    remote.shutdown_kernel().await
                });
            let client = DefaultNodeBuilder::default().build(kernel).unwrap();
            kernels.push(async move { client.await.map(|_| ()) });
        }

        let clients = Box::pin(async move { kernels.try_collect::<()>().await.map(|_| ()) });
        let result = tokio::time::timeout(
            Duration::from_secs(120),
            futures::future::try_select(server, clients),
        )
        .await;
        assert!(result.expect("test timed out").is_ok());
        assert_eq!(client_success.load(Ordering::Relaxed), 2);
    }
}
