//! An unpaced burst over the Unreliable transport: the case the UDP media tests used to
//! hide behind 1 ms pacing sleeps. `send_frame` never blocks and reports zero evictions,
//! so a burst is a legal use of the API. It loses datagrams for real: the UDP send queue
//! evicts its oldest entries past `UDP_OUTBOUND_MAX_QUEUED`, and the loopback socket
//! buffer overflows. The receiver must report every such loss as a `Gap`, the head too.
//!
//! What it must never do is lose a frame silently or discard one it did receive. It
//! locked onto the lowest arrival, so an evicted head vanished without a `Gap`; and when
//! the reliable `EndOfStream` outran a UDP tail stalled behind a hole, its deadline
//! reported the whole tail missing (`Gap 8..=159` with 136 of 160 frames completed) and
//! left the received frames parked in the jitter buffer.
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
    async fn p2p_udp_audio_burst_delivers_every_received_frame() {
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
                        let mut ledger = DeliveryLedger::default();
                        loop {
                            match rx.next_event().await {
                                MediaEvent::Tracks(t) => assert_eq!(t, vec![descriptor.clone()]),
                                MediaEvent::Frame(frame) => {
                                    let (ts, payload) =
                                        &frames[ledger.frame(frame.header.sequence)];
                                    assert_eq!(frame.header.timestamp, *ts);
                                    assert_eq!(&frame.payload, payload, "byte-exact reassembly");
                                }
                                MediaEvent::Gap {
                                    missing_from,
                                    missing_to,
                                    ..
                                } => ledger.gap(missing_from, missing_to),
                                MediaEvent::EndOfStream(track) => {
                                    assert_eq!(track, TRACK);
                                    break;
                                }
                                MediaEvent::Closed => panic!("closed before end of stream"),
                            }
                        }
                        ledger.finish_unreliable(frames.len(), &rx.stats());
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
