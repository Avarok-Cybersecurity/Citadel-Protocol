//! What the primary stream's reader holds for a frame it has not received yet.

use super::primary_stream_reader;
use citadel_io::tokio;
use citadel_io::tokio::io::AsyncWriteExt;
use futures::StreamExt;
use std::time::Duration;

/// What the reader may hold before the bytes of a frame arrive: one read's worth.
const HELD_BEFORE_BYTES_ARRIVE: usize = 128 * 1024;

#[tokio::test]
async fn a_length_prefix_alone_reserves_no_more_than_a_read() {
    let (mut peer, ours) = tokio::io::duplex(1024);
    let mut reader = primary_stream_reader(ours);
    let declared = (64u32 * 1024 * 1024) - 1;
    peer.write_all(&declared.to_be_bytes()).await.unwrap();
    // The frame never completes: the reader parks after taking the prefix.
    let pending = tokio::time::timeout(Duration::from_millis(50), reader.next()).await;
    assert!(pending.is_err(), "a frame with no body was yielded");
    let held = reader.read_buffer().capacity();
    assert!(
        held <= HELD_BEFORE_BYTES_ARRIVE,
        "four bytes of prefix reserved {held} bytes"
    );
}

#[tokio::test]
async fn frames_arriving_in_pieces_are_read_whole() {
    let (mut peer, ours) = tokio::io::duplex(1024);
    let mut reader = primary_stream_reader(ours);
    let body: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
    let frames = [&body[..], &[][..], &body[..17]];
    let write = async {
        for frame in frames {
            peer.write_all(&(frame.len() as u32).to_be_bytes())
                .await
                .unwrap();
            for piece in frame.chunks(777) {
                peer.write_all(piece).await.unwrap();
            }
        }
    };
    let read = async {
        let mut read = Vec::new();
        for _ in 0..frames.len() {
            read.push(reader.next().await.unwrap().unwrap());
        }
        read
    };
    let ((), read) = tokio::join!(write, read);
    for (frame, read) in frames.iter().zip(read) {
        assert_eq!(&read[..], *frame);
    }
}
