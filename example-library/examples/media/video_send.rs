//! # Media Example: Video Sender
//!
//! Streams a VP8 IVF file to a peer over Citadel's UDP media transport in
//! real time. Each IVF frame becomes one media frame; the keyframe flag comes
//! from the VP8 frame tag; pacing follows `pts x timebase`.
//!
//! Timestamp unit: the wire timestamp is the IVF `pts` verbatim, and the
//! announced track `clock_rate` carries the timebase as ticks-per-second
//! (`timebase_den / timebase_num`), so the receiver can rebuild an equivalent
//! IVF header without extra signaling.
//!
//! ## Usage
//! ```bash
//! export CITADEL_SERVER_ADDR="127.0.0.1:25021" # e.g. `cargo run --example server_basic`
//! export CITADEL_MY_USER="video_sender"
//! export CITADEL_OTHER_USER="video_receiver"
//! export CITADEL_MEDIA_FILE="vp80-05-sharpness-1428.ivf" # see common::IVF_FIXTURE_URL
//! cargo run --example media_video_send
//! ```
//! Run `media_video_recv` in another terminal with the users swapped.

#[path = "common.rs"]
mod common;

use bytes::BytesMut;
use citadel_media::demux::{vp8_is_keyframe, IvfReader};
use citadel_media::{FrameFlags, MediaTrackDescriptor, TrackId, TrackKind};
use citadel_sdk::media::MediaEndpoint;
use citadel_sdk::prelude::NetworkError;
use std::fs::File;
use std::time::Duration;

const VIDEO_TRACK: TrackId = TrackId(0);
/// Lets in-flight datagrams and the end-of-stream control message land.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = common::media_input(common::IVF_FIXTURE_URL);
    let cfg = common::transport_config();
    // Open and parse the header before connecting so a bad file fails fast.
    // The per-frame allocation bound is the transport's own frame limit.
    let mut reader = IvfReader::new(File::open(&input)?, cfg.media.max_frame_bytes)?;
    let header = *reader.header();
    if header.timebase_num == 0 || header.timebase_den % header.timebase_num != 0 {
        return Err(format!(
            "IVF timebase {}/{} is not expressible as an integer ticks-per-second clock",
            header.timebase_num, header.timebase_den
        )
        .into());
    }
    let clock_rate = header.timebase_den / header.timebase_num;
    println!(
        "Streaming {}: {}x{} {} @ timebase {}/{} ({} frames)",
        input.display(),
        header.width,
        header.height,
        String::from_utf8_lossy(&header.fourcc),
        header.timebase_num,
        header.timebase_den,
        header.frame_count
    );

    common::run_media_peer(move |conn| async move {
        let (endpoint, _peer_remote) = MediaEndpoint::from_peer_connection(conn, cfg).await?;
        println!("Media transport: {:?}", endpoint.kind());
        let (mut tx, rx) = endpoint.split();

        let descriptor = MediaTrackDescriptor {
            track: VIDEO_TRACK,
            kind: TrackKind::Video,
            clock_rate, // ticks per second == timebase_den / timebase_num
            codec: header.fourcc,
            channels: 0,
            width: header.width,
            height: header.height,
            name: "video".to_owned(),
        };
        tx.announce(std::slice::from_ref(&descriptor)).await?;

        let mut scratch = BytesMut::new();
        let start = tokio::time::Instant::now();
        let mut keyframes = 0u64;
        while let Some(frame) = reader.next_frame(&mut scratch).map_err(common::net_err)? {
            // Real-time pacing: present each frame at pts x timebase.
            let due = header
                .pts_to_micros(frame.pts)
                .ok_or_else(|| NetworkError::msg("IVF timebase_den is zero"))?;
            tokio::time::sleep_until(start + Duration::from_micros(due)).await;
            let flags = if vp8_is_keyframe(&frame.data) {
                keyframes += 1;
                FrameFlags::KEYFRAME
            } else {
                FrameFlags::NONE
            };
            let timestamp = u32::try_from(frame.pts).map_err(common::net_err)?;
            let dropped =
                tx.send_frame(VIDEO_TRACK, TrackKind::Video, timestamp, flags, frame.data)?;
            if dropped > 0 {
                println!("send queue evicted {dropped} frame(s)");
            }
        }

        tx.end_of_stream(VIDEO_TRACK).await?;
        tokio::time::sleep(SHUTDOWN_GRACE).await;
        let stats = tx.stats();
        println!(
            "Done: {} frames ({keyframes} keyframes) / {} fragments / {} bytes sent",
            stats.frames_sent, stats.fragments_sent, stats.bytes_sent
        );
        // Keep the receive half alive until now: dropping it earlier would
        // signal DisconnectUDP to the peer mid-stream.
        drop(rx);
        Ok::<(), NetworkError>(())
    })
    .await
}
