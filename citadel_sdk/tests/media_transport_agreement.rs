//! Both ends of a media session must agree on the transport. Each side picks
//! UDP or the reliable fallback from its own `udp_wait` timer; when one side's
//! UDP channel is delivered after that side's timer expired (a stall on that
//! side only), the sides must still end up on the same transport and media
//! must flow in both directions.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::media::test_media_config;
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
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use uuid::Uuid;

    const TRACK: TrackId = TrackId(0);
    const FRAMES: u32 = 16;

    fn descriptor() -> MediaTrackDescriptor {
        MediaTrackDescriptor {
            track: TRACK,
            kind: TrackKind::Audio,
            clock_rate: 48_000,
            codec: *b"PCM\0",
            channels: 1,
            width: 0,
            height: 0,
            name: "audio".into(),
        }
    }

    fn payload(sender: usize, i: u32) -> Bytes {
        Bytes::from(vec![(sender as u8) ^ (i as u8); 200])
    }

    /// Per-side outcome, asserted after both kernels finish.
    #[derive(Debug, Default, Clone)]
    struct Outcome {
        kind: Option<MediaTransportKind>,
        send_errors: Vec<String>,
        received: Vec<Bytes>,
        ended_by: Option<String>,
    }

    /// Side 1's UDP channel is withheld until its endpoint has finished
    /// building, i.e. until after its own `udp_wait` has elapsed. That is the
    /// observable effect of a stall on side 1 alone. Side 0 is untouched.
    #[rstest]
    #[timeout(Duration::from_secs(150))]
    #[tokio::test(flavor = "multi_thread")]
    async fn late_udp_on_one_side_still_agrees_and_flows_both_ways() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let outcomes: &Mutex<[Outcome; 2]> = &Mutex::new(Default::default());
        let (server, server_addr) = server_info::<StackedRatchet>();
        let uuids = [Uuid::new_v4(), Uuid::new_v4()];
        let kernels = FuturesUnordered::new();

        for idx in 0..2 {
            let other = uuids[1 - idx];
            let late_side = idx == 1;
            let agg = PeerConnectionSetupAggregator::default()
                .with_peer_custom(other)
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
                    // Each side learns the other's version from its key-exchange stage
                    // (the initiator from Stage1, the responder from Stage2); without it the
                    // endpoint would not negotiate at all.
                    assert_eq!(
                        conn.channel.peer_protocol_version(),
                        Some(*citadel_proto::constants::PROTOCOL_VERSION),
                        "side {idx}: the peer's protocol version did not reach the channel"
                    );
                    let cfg = test_media_config();
                    let real_udp_rx = conn.udp_channel_rx;
                    let _peer_remote = conn.remote;
                    assert!(
                        real_udp_rx.is_some(),
                        "UdpMode::Enabled yields a UDP receiver"
                    );

                    let (endpoint, forwarder) = if late_side {
                        let (late_tx, late_rx) = oneshot::channel();
                        let (built_tx, built_rx) = oneshot::channel::<()>();
                        let forwarder = tokio::spawn(async move {
                            let chan = real_udp_rx.unwrap().await.expect("UDP channel");
                            let _ = built_rx.await;
                            // The endpoint gave up on UDP; exactly what the
                            // session does with a late channel: send, and
                            // drop it if nobody is listening any more.
                            let _ = late_tx.send(chan);
                        });
                        let endpoint =
                            MediaEndpoint::from_channels(conn.channel, Some(late_rx), cfg)
                                .await
                                .unwrap();
                        let _ = built_tx.send(());
                        (endpoint, Some(forwarder))
                    } else {
                        let endpoint = MediaEndpoint::from_channels(conn.channel, real_udp_rx, cfg)
                            .await
                            .unwrap();
                        (endpoint, None)
                    };
                    if let Some(forwarder) = forwarder {
                        forwarder.await.unwrap();
                    }
                    outcomes.lock().unwrap()[idx].kind = Some(endpoint.kind());
                    let (mut tx, mut rx) = endpoint.split();
                    wait_for_peers().await;

                    let send = async {
                        let mut errors = Vec::new();
                        if let Err(e) = tx.announce(&[descriptor()]).await {
                            errors.push(format!("announce: {e}"));
                        }
                        for i in 0..FRAMES {
                            if let Err(e) = tx.send_frame(
                                TRACK,
                                TrackKind::Audio,
                                i * 960,
                                FrameFlags::KEYFRAME,
                                payload(idx, i),
                            ) {
                                errors.push(format!("frame {i}: {e}"));
                            }
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        if let Err(e) = tx.end_of_stream(TRACK).await {
                            errors.push(format!("eos: {e}"));
                        }
                        errors
                    };
                    let recv = async {
                        let mut got = Vec::new();
                        let ended = loop {
                            match rx.next_event().await {
                                MediaEvent::Tracks(_) => {}
                                MediaEvent::Frame(f) => got.push(f.payload),
                                MediaEvent::Gap { .. } => {}
                                MediaEvent::EndOfStream(_) => break "EndOfStream",
                                MediaEvent::Closed => break "Closed",
                            }
                        };
                        (got, ended)
                    };
                    let (errors, (got, ended)) = tokio::join!(send, recv);
                    {
                        let mut o = outcomes.lock().unwrap();
                        o[idx].send_errors = errors;
                        o[idx].received = got;
                        o[idx].ended_by = Some(ended.to_string());
                    }

                    wait_for_peers().await;
                    drop((tx, rx));
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

        let o = outcomes.lock().unwrap().clone();
        let summary: Vec<String> = o
            .iter()
            .enumerate()
            .map(|(i, s)| {
                format!(
                    "side {i}: kind={:?} frames_received={}/{FRAMES} ended_by={:?} send_errors={:?}",
                    s.kind,
                    s.received.len(),
                    s.ended_by,
                    s.send_errors
                )
            })
            .collect();
        let o_summary = summary.join("; ");
        assert_eq!(
            o[0].kind, o[1].kind,
            "both ends must use the same media transport: {o_summary}"
        );
        for (receiver, sender) in [(0usize, 1usize), (1, 0)] {
            let expected: Vec<Bytes> = (0..FRAMES).map(|i| payload(sender, i)).collect();
            assert_eq!(
                o[receiver].received, expected,
                "side {receiver} must receive every frame side {sender} sent: {o_summary}"
            );
        }
        for side in &o {
            assert!(side.send_errors.is_empty(), "send errors: {o_summary}");
        }
    }
}
