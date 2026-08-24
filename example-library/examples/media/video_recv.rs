//! # Media Example: Video Receiver
//!
//! Receives the VP8 stream sent by `media_video_send` and re-muxes it into an
//! IVF file. The announced track carries width/height and the timebase as
//! `clock_rate` ticks-per-second, and each wire timestamp is the original IVF
//! `pts`, so the output header is rebuilt as `timebase = 1 / clock_rate`.
//!
//! Frames are buffered in memory until end-of-stream because the IVF header
//! states the frame count up front.
//!
//! ## Usage
//! ```bash
//! export CITADEL_SERVER_ADDR="127.0.0.1:25021" # e.g. `cargo run --example server_basic`
//! export CITADEL_MY_USER="video_receiver"
//! export CITADEL_OTHER_USER="video_sender"
//! # optional; defaults to ./media_out.ivf (printed on start)
//! export CITADEL_MEDIA_OUT="received.ivf"
//! cargo run --example media_video_recv
//! ```
//! Play the result with e.g. `ffplay media_out.ivf`.

#[path = "common.rs"]
mod common;

use bytes::Bytes;
use citadel_media::demux::{vp8_is_keyframe, IvfHeader, IvfWriter};
use citadel_media::{MediaTrackDescriptor, TrackKind};
use citadel_sdk::media::{MediaEndpoint, MediaEvent};
use citadel_sdk::prelude::NetworkError;
use std::fs::File;
use std::path::Path;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = common::media_output("ivf");

    common::run_media_peer(move |conn| async move {
        let (endpoint, _peer_remote) =
            MediaEndpoint::from_peer_connection(conn, common::transport_config()).await?;
        println!("Media transport: {:?}", endpoint.kind());
        let (mut tx, mut rx) = endpoint.split();

        let mut descriptor: Option<MediaTrackDescriptor> = None;
        let mut frames: Vec<(u64, Bytes)> = Vec::new();
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.tick().await; // an interval's first tick is immediate; skip it
        loop {
            tokio::select! {
                event = rx.next_event() => match event {
                    MediaEvent::Tracks(tracks) => {
                        let video = tracks
                            .iter()
                            .find(|t| t.kind == TrackKind::Video)
                            .cloned()
                            .ok_or_else(|| NetworkError::msg("peer announced no video track"))?;
                        println!(
                            "Track {}: {}x{} {} @ {} ticks/s",
                            video.track.0, video.width, video.height,
                            String::from_utf8_lossy(&video.codec), video.clock_rate
                        );
                        descriptor = Some(video);
                        tx.accept(&tracks).await?;
                    }
                    MediaEvent::Frame(frame) => {
                        // The wire timestamp is the sender's IVF pts (see media_video_send).
                        frames.push((u64::from(frame.header.timestamp), frame.payload));
                    }
                    MediaEvent::Gap { track, missing_from, missing_to } => {
                        println!(
                            "gap on track {}: frames {missing_from}..={missing_to} lost",
                            track.0
                        );
                    }
                    MediaEvent::EndOfStream(track) => {
                        println!("end of stream on track {}", track.0);
                        break;
                    }
                    MediaEvent::Closed => {
                        println!("transport closed before end of stream");
                        break;
                    }
                },
                _ = ticker.tick() => common::print_receiver_stats(&rx),
            }
        }

        let descriptor = descriptor
            .ok_or_else(|| NetworkError::msg("stream ended before any track was announced"))?;
        write_ivf(&out_path, &descriptor, &frames).map_err(common::net_err)?;
        let s = rx.stats();
        println!(
            "Summary: {} frames delivered / {} bytes; {} gaps ({} frames missing)",
            s.frames_delivered, s.bytes_received, s.gaps_skipped, s.frames_missing
        );
        Ok::<(), NetworkError>(())
    })
    .await
}

/// Re-muxes the received frames into an IVF file whose header is rebuilt from
/// the announced track descriptor (`timebase = 1 / clock_rate`).
fn write_ivf(
    path: &Path,
    desc: &MediaTrackDescriptor,
    frames: &[(u64, Bytes)],
) -> Result<(), Box<dyn std::error::Error>> {
    let header = IvfHeader {
        fourcc: desc.codec,
        width: desc.width,
        height: desc.height,
        timebase_den: desc.clock_rate,
        timebase_num: 1,
        frame_count: u32::try_from(frames.len())?,
    };
    let mut writer = IvfWriter::new(File::create(path)?, &header)?;
    for (pts, data) in frames {
        writer.write_frame(*pts, data)?;
    }
    writer.finish()?;
    let keyframes = frames.iter().filter(|(_, d)| vp8_is_keyframe(d)).count();
    println!(
        "Wrote {} frames ({keyframes} keyframes) to {}",
        frames.len(),
        path.display()
    );
    Ok(())
}
