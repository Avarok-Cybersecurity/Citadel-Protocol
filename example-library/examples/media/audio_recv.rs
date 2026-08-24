//! # Media Example: Audio Receiver
//!
//! Receives the PCM stream sent by `media_audio_send`, writes the raw
//! little-endian sample data to a file, and prints jitter/gap statistics once
//! per second plus a final summary.
//!
//! ## Usage
//! ```bash
//! export CITADEL_SERVER_ADDR="127.0.0.1:25021" # e.g. `cargo run --example server_basic`
//! export CITADEL_MY_USER="audio_receiver"
//! export CITADEL_OTHER_USER="audio_sender"
//! # optional; defaults to ./media_out.pcm (printed on start)
//! export CITADEL_MEDIA_OUT="received.pcm"
//! cargo run --example media_audio_recv
//! ```
//! Play the result with e.g. `ffplay -f s16le -ar 44100 -ch_layout stereo media_out.pcm`
//! (match the rate/channels printed from the announced track).

#[path = "common.rs"]
mod common;

use citadel_sdk::media::{MediaEndpoint, MediaEvent};
use citadel_sdk::prelude::NetworkError;
use std::fs::File;
use std::io::Write;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = common::media_output("pcm");

    common::run_media_peer(move |conn| async move {
        let (endpoint, _peer_remote) =
            MediaEndpoint::from_peer_connection(conn, common::transport_config()).await?;
        println!("Media transport: {:?}", endpoint.kind());
        let (mut tx, mut rx) = endpoint.split();
        let mut out = File::create(&out_path).map_err(common::net_err)?;

        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.tick().await; // an interval's first tick is immediate; skip it
        loop {
            tokio::select! {
                event = rx.next_event() => match event {
                    MediaEvent::Tracks(tracks) => {
                        for t in &tracks {
                            println!(
                                "Track {}: {:?} '{}' @ {} Hz, {} channel(s)",
                                t.track.0, t.kind, t.name, t.clock_rate, t.channels
                            );
                        }
                        tx.accept(&tracks).await?;
                    }
                    MediaEvent::Frame(frame) => {
                        out.write_all(&frame.payload).map_err(common::net_err)?;
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

        out.flush().map_err(common::net_err)?;
        let s = rx.stats();
        println!(
            "Summary: {} frames delivered / {} bytes; {} gaps ({} frames missing), \
             {} late, {} too old, {} evicted incomplete",
            s.frames_delivered,
            s.bytes_received,
            s.gaps_skipped,
            s.frames_missing,
            s.frames_late,
            s.frames_too_old,
            s.frames_evicted_incomplete
        );
        println!("Wrote raw PCM to {}", out_path.display());
        Ok::<(), NetworkError>(())
    })
    .await
}
