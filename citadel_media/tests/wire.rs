mod common;

use citadel_media::wire::{self, MSG_TYPE_CONTROL, MSG_TYPE_FRAGMENT};
use citadel_media::{
    FragmentHeader, FrameFlags, FrameHeader, MediaError, TrackId, TrackKind, WireMessage,
    FRAGMENT_HEADER_LEN, WIRE_VERSION,
};
use rstest::rstest;

fn header() -> FragmentHeader {
    FragmentHeader {
        frame: FrameHeader {
            track: TrackId(7),
            kind: TrackKind::Video,
            sequence: 0xDEAD_BEEF,
            timestamp: 0x0102_0304,
            flags: FrameFlags::KEYFRAME | FrameFlags::DISCARDABLE,
        },
        total_len: 70_000,
        frag_index: 3,
        frag_count: 64,
    }
}

#[test]
fn layout_is_big_endian_and_20_bytes() {
    let bytes = header().encode();
    assert_eq!(bytes.len(), FRAGMENT_HEADER_LEN);
    assert_eq!(bytes[0], WIRE_VERSION);
    assert_eq!(bytes[1], MSG_TYPE_FRAGMENT);
    assert_eq!(bytes[2], 7);
    assert_eq!(bytes[3], 0x13);
    assert_eq!(&bytes[4..8], &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(&bytes[8..12], &[1, 2, 3, 4]);
    assert_eq!(&bytes[12..16], &70_000u32.to_be_bytes());
    assert_eq!(&bytes[16..18], &[0, 3]);
    assert_eq!(&bytes[18..20], &[0, 64]);
}

#[test]
fn roundtrip_through_parse() {
    let mut datagram = header().encode().to_vec();
    datagram.extend_from_slice(b"payload");
    match wire::parse(&datagram).unwrap() {
        WireMessage::Fragment { header: h, payload } => {
            assert_eq!(h, header());
            assert_eq!(payload, b"payload");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn control_roundtrip() {
    let datagram = wire::encode_control(&[9, 8, 7]);
    assert_eq!(&datagram[..2], &[WIRE_VERSION, MSG_TYPE_CONTROL]);
    assert_eq!(wire::parse(&datagram), Ok(WireMessage::Control(&[9, 8, 7])));
}

fn mutated(f: impl FnOnce(&mut [u8; FRAGMENT_HEADER_LEN])) -> Vec<u8> {
    let mut h = header().encode();
    f(&mut h);
    h.to_vec()
}

#[rstest]
#[case::empty(vec![], MediaError::HeaderTooShort { len: 0, need: 2 })]
#[case::short(vec![WIRE_VERSION, MSG_TYPE_FRAGMENT, 0], MediaError::HeaderTooShort { len: 3, need: 20 })]
#[case::version(mutated(|h| h[0] = 2), MediaError::UnsupportedVersion(2))]
#[case::msg_type(mutated(|h| h[1] = 9), MediaError::UnknownMessageType(9))]
#[case::kind(mutated(|h| h[3] = 0x20), MediaError::UnknownTrackKind(2))]
#[case::flags(mutated(|h| h[3] = 0x18), MediaError::ReservedFlags(8))]
#[case::count_zero(mutated(|h| { h[18] = 0; h[19] = 0; }), MediaError::FragmentCountZero)]
#[case::index_oob(mutated(|h| { h[16] = 0; h[17] = 64; }), MediaError::FragmentIndexOutOfRange { index: 64, count: 64 })]
fn negative_cases(#[case] datagram: Vec<u8>, #[case] expected: MediaError) {
    assert_eq!(wire::parse(&datagram).unwrap_err(), expected);
}
