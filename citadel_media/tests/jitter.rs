mod common;

use citadel_media::{FrameFlags, JitterBuffer, PopResult, PushResult, TrackId};
use common::{at, frame, CFG, T0};

const DEPTH: u64 = CFG.jitter_depth_micros;

fn jb() -> JitterBuffer {
    JitterBuffer::new(CFG).unwrap()
}

fn seq_of(r: PopResult) -> u32 {
    match r {
        PopResult::Frame(f) => f.header.sequence,
        other => panic!("expected frame, got {other:?}"),
    }
}

/// The track locks on only after the hold-back window: reordered frames pushed pre-lock are
/// all delivered, starting from the lowest buffered sequence (not the first arrival).
#[test]
fn lock_on_after_holdback_delivers_from_lowest_sequence() {
    let mut j = jb();
    assert_eq!(j.next_expected(TrackId(0)), None);
    // Reordered arrival: 12 first, then 10 and 11.
    assert_eq!(
        j.push(frame(0, 12, FrameFlags::NONE), T0),
        PushResult::Buffered
    );
    assert_eq!(
        j.push(frame(0, 10, FrameFlags::NONE), T0),
        PushResult::Buffered
    );
    assert_eq!(
        j.push(frame(0, 11, FrameFlags::NONE), T0),
        PushResult::Buffered
    );
    assert_eq!(
        j.next_expected(TrackId(0)),
        None,
        "unlocked until first pop"
    );
    assert_eq!(j.pop_ready(at(DEPTH - 1)), PopResult::NotReady);
    assert_eq!(j.next_deadline(), Some(at(DEPTH)));
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), 10);
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), 11);
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), 12);
    assert_eq!(j.pop_ready(at(DEPTH)), PopResult::NotReady);
    assert_eq!(j.next_deadline(), None);
}

#[test]
fn late_vs_too_old_boundary() {
    let mut j = jb();
    j.push(frame(0, 100, FrameFlags::NONE), T0);
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), 100);
    let window = CFG.max_reorder_window;
    assert_eq!(
        j.push(frame(0, 100, FrameFlags::NONE), T0),
        PushResult::Late
    );
    assert_eq!(
        j.push(frame(0, 101 - window, FrameFlags::NONE), T0),
        PushResult::Late
    );
    assert_eq!(
        j.push(frame(0, 100 - window, FrameFlags::NONE), T0),
        PushResult::TooOld
    );
    assert_eq!(
        j.push(frame(0, 101, FrameFlags::NONE), T0),
        PushResult::Buffered
    );
    assert_eq!(
        j.push(frame(0, 101, FrameFlags::NONE), T0),
        PushResult::Duplicate
    );
}

#[test]
fn gap_skipped_after_jitter_depth() {
    let mut j = jb();
    j.push(frame(0, 0, FrameFlags::NONE), T0);
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), 0); // locked; next_expected = 1
    j.push(frame(0, 3, FrameFlags::NONE), at(DEPTH + 100));
    j.push(frame(0, 4, FrameFlags::NONE), at(DEPTH + 200));
    assert_eq!(j.pop_ready(at(2 * DEPTH + 99)), PopResult::NotReady);
    assert_eq!(j.next_deadline(), Some(at(2 * DEPTH + 100)));
    match j.pop_ready(at(2 * DEPTH + 100)) {
        PopResult::Gap {
            track,
            missing_from,
            missing_to,
            next,
        } => {
            assert_eq!(track, TrackId(0));
            assert_eq!((missing_from, missing_to), (1, 2));
            assert_eq!(next.header.sequence, 3);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(seq_of(j.pop_ready(at(2 * DEPTH + 100))), 4);
    assert_eq!(j.push(frame(0, 1, FrameFlags::NONE), T0), PushResult::Late);
}

#[test]
fn next_deadline_tracks_lock_on_and_in_order_arrivals() {
    let mut j = jb();
    // Unlocked track: something may become ready only after the hold-back matures.
    j.push(frame(0, 5, FrameFlags::NONE), at(50));
    assert_eq!(j.next_deadline(), Some(at(50 + DEPTH)));
    assert_eq!(seq_of(j.pop_ready(at(50 + DEPTH))), 5);
    // Locked track with the in-order frame buffered: ready at its arrival.
    j.push(frame(0, 6, FrameFlags::NONE), at(60 + DEPTH));
    assert_eq!(j.next_deadline(), Some(at(60 + DEPTH)));
    assert_eq!(j.buffered_len(), 1);
}

#[test]
fn tracks_are_independent() {
    let mut j = jb();
    j.push(frame(3, 7, FrameFlags::NONE), T0);
    j.push(frame(9, 1, FrameFlags::NONE), T0);
    assert_eq!(j.next_expected(TrackId(3)), None);
    assert_eq!(j.next_expected(TrackId(9)), None);
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), 7);
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), 1);
    assert_eq!(j.next_expected(TrackId(3)), Some(8));
    assert_eq!(j.next_expected(TrackId(9)), Some(2));
}

#[test]
fn sequence_wraps_around_u32() {
    let mut j = jb();
    j.push(frame(0, u32::MAX - 1, FrameFlags::NONE), T0);
    assert_eq!(
        j.push(frame(0, 1, FrameFlags::NONE), T0),
        PushResult::Buffered
    );
    assert_eq!(
        j.push(frame(0, 0, FrameFlags::NONE), T0),
        PushResult::Buffered
    );
    assert_eq!(
        j.push(frame(0, u32::MAX, FrameFlags::NONE), T0),
        PushResult::Buffered
    );
    // Lock-on picks the wrap-aware lowest (MAX-1), then delivers across the wrap in order.
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), u32::MAX - 1);
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), u32::MAX);
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), 0);
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), 1);
    assert_eq!(j.next_expected(TrackId(0)), Some(2));
    assert_eq!(
        j.push(frame(0, u32::MAX, FrameFlags::NONE), T0),
        PushResult::Late
    );
}

#[test]
fn gap_across_wrap() {
    let mut j = jb();
    j.push(frame(0, u32::MAX - 1, FrameFlags::NONE), T0);
    assert_eq!(seq_of(j.pop_ready(at(DEPTH))), u32::MAX - 1);
    j.push(frame(0, 1, FrameFlags::NONE), at(DEPTH));
    match j.pop_ready(at(2 * DEPTH)) {
        PopResult::Gap {
            missing_from,
            missing_to,
            ..
        } => {
            assert_eq!((missing_from, missing_to), (u32::MAX, 0));
        }
        other => panic!("{other:?}"),
    }
}
