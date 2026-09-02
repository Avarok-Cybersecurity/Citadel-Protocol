//! UDP media transport mode/robustness tests: C2S streaming over the server's raw-UDP path,
//! oversized-datagram containment, explicit per-channel security levels, and the fixture
//! download-and-cache mechanism itself.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::fixtures::{
        ensure, ensure_bytes, Fixture, FixtureError, FIXTURE_DIR_ENV, OFFLINE_ENV,
    };
    use crate::common::media::*;
    use bytes::BytesMut;
    use citadel_io::tokio;
    use citadel_io::ErrorCode;
    use citadel_sdk::citadel_media::descriptor::MediaTrackDescriptor;
    use citadel_sdk::citadel_media::frame::{FrameFlags, TrackId, TrackKind};
    use citadel_sdk::media::{MediaEndpoint, MediaEvent, MediaTransportKind};
    use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info_reactive, wait_for_peers, TestBarrier};

    /// Await one datagram, bounded, saying what was being waited for.
    ///
    /// UDP does not promise delivery and these assertions awaited it unbounded,
    /// so one dropped datagram parked the test until its timeout with no
    /// indication of which exchange stalled — the shape that made a 180s hang in
    /// the peer-to-peer transfer test unreadable until it was bounded.
    ///
    /// Bounding, not resending. The echo here is strictly counted: the server
    /// echoes exactly two payloads, so a resent datagram would draw an extra
    /// echo, exhaust that count early and strand the second exchange. Making the
    /// test tolerate loss needs the echo protocol changed, which is a larger
    /// change than this earns; naming the failure is what is safe to do now.
    async fn recv_bounded<S>(rx: &mut S, waiting_for: &str) -> S::Item
    where
        S: futures::Stream + Unpin,
    {
        use futures::StreamExt;
        const BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
        match citadel_io::tokio::time::timeout(BUDGET, rx.next()).await {
            Ok(Some(item)) => item,
            Ok(None) => panic!("the UDP channel closed before {waiting_for} arrived"),
            Err(_) => panic!("no UDP datagram within {BUDGET:?} while waiting for {waiting_for}"),
        }
    }
    use rstest::rstest;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use uuid::Uuid;

    const TRACK: TrackId = TrackId(0);

    /// Client streams the fixture WAV to the server over the C2S UDP channel; the server
    /// reassembles and checks byte-exactness. C2S over a TCP primary stream exercises the raw
    /// hole-punched UDP socket path (no QUIC datagrams).
    #[rstest]
    #[timeout(Duration::from_secs(150))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn c2s_udp_media_stream() {
        citadel_logging::setup_log();
        let Some(bytes) = ensure_bytes(Fixture::Wav).unwrap() else {
            return;
        };
        TestBarrier::setup(2);
        let (sample_rate, chunks) = wav_chunks(&bytes);
        let expected_hash = sha_of_parts(chunks.iter().map(|c| c.as_ref()));
        let expected_count = chunks.len();

        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);

        let server_hash = expected_hash.clone();
        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            move |mut connection| {
                let server_hash = server_hash.clone();
                async move {
                    let endpoint = MediaEndpoint::from_c2s(&mut connection, test_media_config())
                        .await
                        .unwrap();
                    assert_eq!(endpoint.kind(), MediaTransportKind::Unreliable);
                    let (_tx, mut rx) = endpoint.split();
                    wait_for_peers().await;
                    let mut got = Vec::new();
                    loop {
                        match rx.next_event().await {
                            MediaEvent::Tracks(_) => {}
                            MediaEvent::Frame(frame) => got.push(frame.payload),
                            MediaEvent::Gap {
                                missing_from,
                                missing_to,
                                ..
                            } => {
                                panic!("loss on loopback: {missing_from}..={missing_to}")
                            }
                            MediaEvent::EndOfStream(track) => {
                                assert_eq!(track, TRACK);
                                break;
                            }
                            MediaEvent::Closed => panic!("closed early"),
                        }
                    }
                    assert_eq!(got.len(), expected_count);
                    assert_eq!(sha_of_parts(got.iter().map(|p| p.as_ref())), server_hash);
                    server_success.store(true, Ordering::SeqCst);
                    wait_for_peers().await;
                    connection.shutdown_kernel().await
                }
            },
            |_| {},
        );

        let client_settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, Uuid::new_v4())
                .with_udp_mode(UdpMode::Enabled)
                .build()
                .unwrap();
        let client_kernel =
            SingleClientServerConnectionKernel::new(client_settings, move |mut connection| {
                let chunks = chunks.clone();
                async move {
                    let endpoint = MediaEndpoint::from_c2s(&mut connection, test_media_config())
                        .await
                        .unwrap();
                    assert_eq!(endpoint.kind(), MediaTransportKind::Unreliable);
                    let (mut tx, _rx) = endpoint.split();
                    wait_for_peers().await;
                    tx.announce(&[MediaTrackDescriptor {
                        track: TRACK,
                        kind: TrackKind::Audio,
                        clock_rate: sample_rate,
                        codec: *b"PCM\0",
                        channels: 2,
                        width: 0,
                        height: 0,
                        name: "audio".into(),
                    }])
                    .await
                    .unwrap();
                    let samples = (sample_rate as u64 * AUDIO_FRAME_MICROS / 1_000_000) as u32;
                    for (i, chunk) in chunks.iter().enumerate() {
                        let dropped = tx
                            .send_frame(
                                TRACK,
                                TrackKind::Audio,
                                i as u32 * samples,
                                FrameFlags::KEYFRAME,
                                chunk.clone(),
                            )
                            .unwrap();
                        assert_eq!(dropped, 0);
                        // Light pacing: real capture is paced 20 ms/frame; an unpaced burst
                        // overflows the loopback UDP socket buffer and loses the tail.
                        if i % 4 == 3 {
                            citadel_io::tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }
                    tx.end_of_stream(TRACK).await.unwrap();
                    client_success.store(true, Ordering::Relaxed);
                    wait_for_peers().await;
                    connection.shutdown_kernel().await
                }
            });

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
        let result = citadel_io::tokio::time::timeout(
            Duration::from_secs(120),
            futures::future::try_select(server, Box::pin(async move { client.await.map(|_| ()) })),
        )
        .await;
        assert!(result.expect("timed out").is_ok());
        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::SeqCst));
    }

    /// An oversized payload must be rejected at the sender without killing the UDP subsystem,
    /// and an explicitly raised security level must round-trip.
    #[rstest]
    #[timeout(Duration::from_secs(90))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn udp_oversized_rejected_and_security_level_explicit() {
        citadel_logging::setup_log();
        TestBarrier::setup(2);
        let client_success = &AtomicBool::new(false);
        let server_success = &AtomicBool::new(false);

        let security = SessionSecuritySettingsBuilder::default()
            .with_security_level(SecurityLevel::Reinforced)
            .build()
            .unwrap();

        let (server, server_addr) = server_info_reactive::<_, _, StackedRatchet>(
            move |mut connection| async move {
                let chan = connection.udp_channel_rx.take().unwrap().await.unwrap();
                let (tx, mut rx) = chan.split();
                wait_for_peers().await;
                // Echo two payloads back (whatever level the client used; receiver is
                // self-describing).
                for exchange in ["first", "second"] {
                    let msg = recv_bounded(&mut rx, exchange).await;
                    tx.unbounded_send(msg.as_ref()).unwrap();
                }
                server_success.store(true, Ordering::SeqCst);
                citadel_sdk::test_common::finish_udp_channel(tx, rx).await;
                connection.shutdown_kernel().await
            },
            |_| {},
        );

        let client_settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, Uuid::new_v4())
                .with_udp_mode(UdpMode::Enabled)
                .with_session_security_settings(security)
                .build()
                .unwrap();
        let client_kernel = SingleClientServerConnectionKernel::new(
            client_settings,
            move |mut connection| async move {
                let chan = connection.udp_channel_rx.take().unwrap().await.unwrap();
                let (mut tx, mut rx) = chan.split();
                wait_for_peers().await;

                // 1. Oversized: rejected fast, channel stays usable.
                let max = tx.max_payload_len();
                let err = tx.unbounded_send(BytesMut::zeroed(max + 1)).unwrap_err();
                assert_eq!(err.code(), ErrorCode::UdpDatagramTooLarge);
                tx.unbounded_send(b"standard level" as &[u8]).unwrap();
                let echoed = recv_bounded(&mut rx, "the standard-level echo").await;
                assert_eq!(echoed.as_ref(), b"standard level");

                // 2. Raised security level: budget shrinks by one AEAD layer and data round-trips.
                tx.set_security_level(SecurityLevel::Reinforced);
                assert_eq!(tx.max_payload_len(), max - 32);
                tx.unbounded_send(b"reinforced level" as &[u8]).unwrap();
                let echoed = recv_bounded(&mut rx, "the reinforced-level echo").await;
                assert_eq!(echoed.as_ref(), b"reinforced level");

                client_success.store(true, Ordering::Relaxed);
                citadel_sdk::test_common::finish_udp_channel(tx, rx).await;
                connection.shutdown_kernel().await
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
        let result = citadel_io::tokio::time::timeout(
            Duration::from_secs(60),
            futures::future::try_select(server, Box::pin(async move { client.await.map(|_| ()) })),
        )
        .await;
        assert!(result.expect("timed out").is_ok());
        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::SeqCst));
    }

    // ── Fixture mechanism (no network) ──────────────────────────────────

    struct EnvGuard(&'static str);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    #[test]
    fn fixture_sha256_mismatch_is_an_error_not_a_redownload() {
        let dir =
            std::env::temp_dir().join(format!("citadel_fixture_mismatch_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(Fixture::Wav.file_name()),
            b"definitely not the wav",
        )
        .unwrap();
        let _guard = EnvGuard(FIXTURE_DIR_ENV);
        std::env::set_var(FIXTURE_DIR_ENV, &dir);
        let err = ensure(Fixture::Wav).unwrap_err();
        assert!(
            matches!(
                err,
                FixtureError::Sha256Mismatch {
                    fixture: Fixture::Wav,
                    ..
                }
            ),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fixture_offline_and_absent_returns_none() {
        let dir =
            std::env::temp_dir().join(format!("citadel_fixture_offline_{}", std::process::id()));
        let _guard = EnvGuard(FIXTURE_DIR_ENV);
        let _offline = EnvGuard(OFFLINE_ENV);
        std::env::set_var(FIXTURE_DIR_ENV, &dir);
        std::env::set_var(OFFLINE_ENV, "1");
        assert!(ensure(Fixture::Vp8Ivf).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
