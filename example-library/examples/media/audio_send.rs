//! # Media Example: Audio Sender
//!
//! Streams a PCM WAV file to a peer over Citadel's UDP media transport in
//! real time: one media frame per 20 ms of audio, paced by a tokio interval,
//! timestamps advancing in samples (the track clock is the WAV sample rate).
//!
//! ## Usage
//! ```bash
//! export CITADEL_SERVER_ADDR="127.0.0.1:25021" # e.g. `cargo run --example server_basic`
//! export CITADEL_MY_USER="audio_sender"
//! export CITADEL_OTHER_USER="audio_receiver"
//! export CITADEL_MEDIA_FILE="sample-3s.wav"    # see common::WAV_FIXTURE_URL
//! cargo run --example media_audio_send
//! ```
//! Run `media_audio_recv` in another terminal with the users swapped.

#[path = "common.rs"]
mod common;

use bytes::BytesMut;
use citadel_media::demux::WavReader;
use citadel_media::{FrameFlags, MediaTrackDescriptor, TrackId, TrackKind};
use citadel_sdk::media::MediaEndpoint;
use citadel_sdk::prelude::NetworkError;
use std::fs::File;
use std::time::Duration;

const AUDIO_TRACK: TrackId = TrackId(0);
/// Each media frame carries 20 ms of audio.
const FRAME_MICROS: u64 = 20_000;
/// Lets in-flight datagrams and the end-of-stream control message land.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = common::media_input(common::WAV_FIXTURE_URL);
    // Open and parse the WAV before connecting so a bad file fails fast.
    let mut wav = WavReader::new(File::open(&input)?)?;
    let format = *wav.format();
    println!(
        "Streaming {}: {} Hz, {} channel(s), {} bit, {} data bytes",
        input.display(),
        format.sample_rate,
        format.channels,
        format.bits_per_sample,
        wav.data_remaining()
    );

    common::run_media_peer(move |conn| async move {
        let (endpoint, _peer_remote) =
            MediaEndpoint::from_peer_connection(conn, common::transport_config()).await?;
        println!("Media transport: {:?}", endpoint.kind());
        let (mut tx, rx) = endpoint.split();

        let descriptor = MediaTrackDescriptor {
            track: AUDIO_TRACK,
            kind: TrackKind::Audio,
            // Timestamps below advance in samples, so the clock is the sample rate.
            clock_rate: format.sample_rate,
            codec: *b"PCM\0",
            channels: u8::try_from(format.channels).map_err(common::net_err)?,
            width: 0,
            height: 0,
            name: format!("pcm{}le", format.bits_per_sample),
        };
        tx.announce(std::slice::from_ref(&descriptor)).await?;

        let mut scratch = BytesMut::new();
        let mut ticker = tokio::time::interval(Duration::from_micros(FRAME_MICROS));
        let mut timestamp = 0u32;
        while let Some(chunk) = wav
            .next_chunk(FRAME_MICROS, &mut scratch)
            .map_err(common::net_err)?
        {
            ticker.tick().await;
            let samples = (chunk.len() / format.block_align as usize) as u32;
            // Raw PCM has no inter-frame dependencies: every frame is a keyframe.
            let dropped = tx.send_frame(
                AUDIO_TRACK,
                TrackKind::Audio,
                timestamp,
                FrameFlags::KEYFRAME,
                chunk,
            )?;
            if dropped > 0 {
                println!("send queue evicted {dropped} frame(s)");
            }
            timestamp = timestamp.wrapping_add(samples);
        }

        tx.end_of_stream(AUDIO_TRACK).await?;
        tokio::time::sleep(SHUTDOWN_GRACE).await;
        let stats = tx.stats();
        println!(
            "Done: {} frames / {} fragments / {} bytes sent ({} dropped on send)",
            stats.frames_sent, stats.fragments_sent, stats.bytes_sent, stats.frames_dropped_on_send
        );
        // Keep the receive half alive until now: dropping it earlier would
        // signal DisconnectUDP to the peer mid-stream.
        drop(rx);
        Ok::<(), NetworkError>(())
    })
    .await
}
