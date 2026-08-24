mod common;

use bytes::Bytes;
use citadel_media::{
    FrameFlags, MediaError, Packetizer, TrackId, TrackKind, WireMessage, FRAGMENT_HEADER_LEN,
};
use common::{payload, CFG};

fn packetizer() -> Packetizer {
    Packetizer::new(CFG).unwrap()
}

fn fragments(p: &mut Packetizer, len: usize) -> Vec<citadel_media::FragmentOut> {
    p.packetize(
        TrackId(1),
        TrackKind::Audio,
        123,
        FrameFlags::NONE,
        payload(len),
    )
    .unwrap()
    .collect()
}

#[test]
fn n_max_plus_one_yields_n_plus_one_fragments() {
    let mut p = packetizer();
    let frags = fragments(&mut p, 3 * CFG.max_fragment_payload + 1);
    assert_eq!(frags.len(), 4);
    assert_eq!(frags[3].payload.len(), 1);
    for (i, f) in frags.iter().enumerate() {
        let WireMessage::Fragment { header, payload } =
            citadel_media::wire::parse(&f.header).unwrap()
        else {
            panic!("not a fragment")
        };
        assert!(payload.is_empty());
        assert_eq!(header.frag_index, i as u16);
        assert_eq!(header.frag_count, 4);
        assert_eq!(header.total_len, 301);
        assert_eq!(header.frame.sequence, 0);
        assert_eq!(header.frame.timestamp, 123);
    }
}

#[test]
fn exact_multiple_has_no_empty_tail() {
    let mut p = packetizer();
    let frags = fragments(&mut p, 2 * CFG.max_fragment_payload);
    assert_eq!(frags.len(), 2);
    assert!(frags
        .iter()
        .all(|f| f.payload.len() == CFG.max_fragment_payload));
}

#[test]
fn slices_are_zero_copy() {
    let mut p = packetizer();
    let src = payload(250);
    let base = src.as_ptr() as usize;
    let frags: Vec<_> = p
        .packetize(
            TrackId(0),
            TrackKind::Video,
            0,
            FrameFlags::NONE,
            src.clone(),
        )
        .unwrap()
        .collect();
    for (i, f) in frags.iter().enumerate() {
        assert_eq!(
            f.payload.as_ptr() as usize,
            base + i * CFG.max_fragment_payload
        );
        assert_eq!(f.wire_len(), FRAGMENT_HEADER_LEN + f.payload.len());
    }
    let mut out = bytes::BytesMut::new();
    frags[0].write_into(&mut out);
    assert_eq!(&out[..FRAGMENT_HEADER_LEN], &frags[0].header);
    assert_eq!(
        &out[FRAGMENT_HEADER_LEN..],
        &src[..CFG.max_fragment_payload]
    );
}

#[test]
fn empty_payload_is_one_fragment() {
    let mut p = packetizer();
    let frags = fragments(&mut p, 0);
    assert_eq!(frags.len(), 1);
    assert!(frags[0].payload.is_empty());
}

#[test]
fn frame_too_large_rejected_without_consuming_sequence() {
    let mut p = packetizer();
    let err = p
        .packetize(
            TrackId(1),
            TrackKind::Audio,
            0,
            FrameFlags::NONE,
            Bytes::from(vec![0; CFG.max_frame_bytes + 1]),
        )
        .unwrap_err();
    assert_eq!(
        err,
        MediaError::FrameTooLarge {
            len: CFG.max_frame_bytes + 1,
            max: CFG.max_frame_bytes
        }
    );
    assert_eq!(p.next_sequence(TrackId(1)), 0);
}

#[test]
fn sequences_are_per_track_and_wrap() {
    let mut p = packetizer();
    p.set_next_sequence(TrackId(2), u32::MAX);
    let a = p
        .packetize(
            TrackId(2),
            TrackKind::Audio,
            0,
            FrameFlags::NONE,
            payload(1),
        )
        .unwrap();
    assert_eq!(a.frame().sequence, u32::MAX);
    let b = p
        .packetize(
            TrackId(2),
            TrackKind::Audio,
            0,
            FrameFlags::NONE,
            payload(1),
        )
        .unwrap();
    assert_eq!(b.frame().sequence, 0);
    assert_eq!(p.next_sequence(TrackId(3)), 0);
    let c = p
        .packetize(
            TrackId(3),
            TrackKind::Video,
            0,
            FrameFlags::KEYFRAME,
            payload(1),
        )
        .unwrap();
    assert_eq!(c.frame().sequence, 0);
    assert_eq!(c.len(), 1);
}

#[test]
fn invalid_config_rejected() {
    let bad = citadel_media::MediaConfig {
        max_fragment_payload: 0,
        ..CFG
    };
    assert!(matches!(
        Packetizer::new(bad),
        Err(MediaError::InvalidConfig(_))
    ));
}
