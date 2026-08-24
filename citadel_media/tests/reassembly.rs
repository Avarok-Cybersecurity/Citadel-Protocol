mod common;

use citadel_media::{
    FragmentOut, FrameFlags, MediaError, Packetizer, ReassembleOutcome, Reassembler, TrackId,
    TrackKind, FRAGMENT_HEADER_LEN,
};
use common::{at, payload, Lcg, CFG, T0};

fn datagram(f: &FragmentOut) -> Vec<u8> {
    let mut d = f.header.to_vec();
    d.extend_from_slice(&f.payload);
    d
}

fn frags(p: &mut Packetizer, track: u8, len: usize) -> Vec<Vec<u8>> {
    p.packetize(
        TrackId(track),
        TrackKind::Video,
        1,
        FrameFlags::KEYFRAME,
        payload(len),
    )
    .unwrap()
    .map(|f| datagram(&f))
    .collect()
}

fn feed_all(r: &mut Reassembler, datagrams: &[Vec<u8>]) -> Vec<ReassembleOutcome> {
    datagrams.iter().map(|d| r.push(d, T0)).collect()
}

#[test]
fn in_order_completes_on_last_fragment() {
    let mut p = Packetizer::new(CFG).unwrap();
    let mut r = Reassembler::new(CFG).unwrap();
    let src = payload(350);
    let d = frags(&mut p, 1, 350);
    let outs = feed_all(&mut r, &d);
    assert_eq!(
        outs[0],
        ReassembleOutcome::Partial {
            received: 1,
            expected: 4
        }
    );
    assert_eq!(
        outs[2],
        ReassembleOutcome::Partial {
            received: 3,
            expected: 4
        }
    );
    let ReassembleOutcome::Complete(frame) = &outs[3] else {
        panic!("{:?}", outs[3])
    };
    assert_eq!(frame.payload, src);
    assert_eq!(frame.header.track, TrackId(1));
    assert!(frame.header.flags.is_keyframe());
    assert_eq!(r.pending_count(), 0);
}

#[test]
fn reverse_and_shuffled_order_complete() {
    let mut p = Packetizer::new(CFG).unwrap();
    let src = payload(999);
    let mut d = frags(&mut p, 0, 999);
    d.reverse();
    let mut r = Reassembler::new(CFG).unwrap();
    let outs = feed_all(&mut r, &d);
    assert!(matches!(outs.last(), Some(ReassembleOutcome::Complete(f)) if f.payload == src));

    let mut rng = Lcg::new(42);
    rng.shuffle(&mut d);
    let mut r = Reassembler::new(CFG).unwrap();
    let outs = feed_all(&mut r, &d);
    assert!(matches!(outs.last(), Some(ReassembleOutcome::Complete(f)) if f.payload == src));
}

#[test]
fn duplicate_fragment_is_reported() {
    let mut p = Packetizer::new(CFG).unwrap();
    let mut r = Reassembler::new(CFG).unwrap();
    let d = frags(&mut p, 0, 250);
    assert!(matches!(
        r.push(&d[0], T0),
        ReassembleOutcome::Partial { .. }
    ));
    assert_eq!(r.push(&d[0], T0), ReassembleOutcome::Duplicate);
    assert_eq!(r.pending_count(), 1);
}

#[test]
fn loss_then_evict_stale() {
    let mut p = Packetizer::new(CFG).unwrap();
    let mut r = Reassembler::new(CFG).unwrap();
    let d = frags(&mut p, 0, 250);
    r.push(&d[0], T0);
    r.push(&d[2], T0);
    assert_eq!(r.evict_stale(at(CFG.jitter_depth_micros - 1)), 0);
    assert_eq!(r.pending_count(), 1);
    assert_eq!(r.evict_stale(at(CFG.jitter_depth_micros)), 1);
    assert_eq!(r.pending_count(), 0);
}

#[test]
fn pending_cap_evicts_oldest() {
    let mut p = Packetizer::new(CFG).unwrap();
    let mut r = Reassembler::new(CFG).unwrap();
    let partials: Vec<_> = (0..=CFG.max_pending_frames)
        .map(|_| frags(&mut p, 0, 250))
        .collect();
    for (i, d) in partials.iter().enumerate() {
        r.push(&d[0], at(i as u64));
    }
    assert_eq!(r.pending_count(), CFG.max_pending_frames);
    assert!(matches!(
        r.push(&partials[0][1], T0),
        ReassembleOutcome::Partial { received: 1, .. }
    ));
    assert_eq!(r.pending_count(), CFG.max_pending_frames);
}

#[test]
fn rejects_oversized_total_len_before_allocating() {
    let mut r = Reassembler::new(CFG).unwrap();
    let mut p = Packetizer::new(citadel_media::MediaConfig {
        max_frame_bytes: CFG.max_frame_bytes * 2,
        ..CFG
    })
    .unwrap();
    let d = frags(&mut p, 0, CFG.max_frame_bytes + 1);
    assert_eq!(
        r.push(&d[0], T0),
        ReassembleOutcome::Rejected(MediaError::FrameTooLarge {
            len: CFG.max_frame_bytes + 1,
            max: CFG.max_frame_bytes
        })
    );
    assert_eq!(r.pending_count(), 0);
}

#[test]
fn header_consistency_checks() {
    let mut p = Packetizer::new(CFG).unwrap();
    let mut r = Reassembler::new(CFG).unwrap();
    let d = frags(&mut p, 0, 250);
    let mut bad_count = d[0].clone();
    bad_count[19] = 2;
    assert_eq!(
        r.push(&bad_count, T0),
        ReassembleOutcome::Rejected(MediaError::TotalLenMismatch {
            expected: 3,
            actual: 2
        })
    );
    let mut short = d[0].clone();
    short.truncate(FRAGMENT_HEADER_LEN + 50);
    assert_eq!(
        r.push(&short, T0),
        ReassembleOutcome::Rejected(MediaError::PayloadLenMismatch {
            expected: 100,
            actual: 50
        })
    );
    r.push(&d[0], T0);
    let mut other_ts = d[1].clone();
    other_ts[11] ^= 1;
    assert_eq!(
        r.push(&other_ts, T0),
        ReassembleOutcome::Rejected(MediaError::FrameHeaderMismatch)
    );
    assert!(matches!(
        r.push(&[0u8; 1], T0),
        ReassembleOutcome::Rejected(_)
    ));
}

#[test]
fn control_messages_are_surfaced() {
    let mut r = Reassembler::new(CFG).unwrap();
    let d = citadel_media::wire::encode_control(&[3, 1]);
    assert_eq!(
        r.push(&d, T0),
        ReassembleOutcome::Control(bytes::Bytes::from_static(&[3, 1]))
    );
}

#[test]
fn shuffled_multi_frame_with_loss_completes_survivors() {
    let mut p = Packetizer::new(CFG).unwrap();
    let mut all = Vec::new();
    for _ in 0..20 {
        all.extend(frags(&mut p, 0, 450));
    }
    let mut rng = Lcg::new(7);
    rng.shuffle(&mut all);
    let kept = rng.apply_loss(all, 10);
    let mut r = Reassembler::new(citadel_media::MediaConfig {
        max_pending_frames: 64,
        ..CFG
    })
    .unwrap();
    let completed = kept
        .iter()
        .filter(|d| matches!(r.push(d, T0), ReassembleOutcome::Complete(_)))
        .count();
    assert!(completed > 0 && completed < 20, "completed {completed}");
    assert_eq!(completed + r.pending_count(), 20);
}
