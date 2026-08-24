use citadel_media::{ControlMessage, MediaError, MediaTrackDescriptor, TrackId, TrackKind};
use rstest::rstest;

fn audio() -> MediaTrackDescriptor {
    MediaTrackDescriptor {
        track: TrackId(1),
        kind: TrackKind::Audio,
        clock_rate: 48_000,
        codec: *b"PCM ",
        channels: 2,
        width: 0,
        height: 0,
        name: "mic".to_owned(),
    }
}

fn video() -> MediaTrackDescriptor {
    MediaTrackDescriptor {
        track: TrackId(2),
        kind: TrackKind::Video,
        clock_rate: 90_000,
        codec: *b"VP80",
        channels: 0,
        width: 352,
        height: 288,
        name: String::new(),
    }
}

#[rstest]
#[case(ControlMessage::AnnounceTracks(vec![audio(), video()]))]
#[case(ControlMessage::AcceptTracks(vec![]))]
#[case(ControlMessage::AcceptTracks(vec![video()]))]
#[case(ControlMessage::EndOfStream { track: TrackId(200), frames_sent: 0 })]
#[case(ControlMessage::EndOfStream { track: TrackId(7), frames_sent: u32::MAX })]
fn roundtrip(#[case] msg: ControlMessage) {
    let body = msg.encode().unwrap();
    assert_eq!(ControlMessage::decode(&body).unwrap(), msg);
}

#[test]
fn layout_is_fixed_plus_name() {
    let body = ControlMessage::AnnounceTracks(vec![audio()])
        .encode()
        .unwrap();
    assert_eq!(body[0], 1);
    assert_eq!(body[1], 1);
    assert_eq!(body.len(), 2 + 16 + 3);
    assert_eq!(&body[4..8], &48_000u32.to_be_bytes());
    assert_eq!(&body[8..12], b"PCM ");
    assert_eq!(body[17], 3);
    assert_eq!(&body[18..], b"mic");
}

#[test]
fn name_over_64_bytes_rejected_on_encode_and_decode() {
    let mut d = audio();
    d.name = "x".repeat(65);
    assert!(matches!(
        ControlMessage::AnnounceTracks(vec![d]).encode(),
        Err(MediaError::DescriptorMalformed(_))
    ));
    let mut body = ControlMessage::AnnounceTracks(vec![audio()])
        .encode()
        .unwrap();
    body[17] = 65;
    assert!(matches!(
        ControlMessage::decode(&body),
        Err(MediaError::DescriptorMalformed(_))
    ));
}

#[rstest]
#[case::empty(vec![])]
#[case::unknown_tag(vec![9])]
#[case::missing_count(vec![1])]
#[case::truncated_descriptor(vec![1, 1, 0, 0])]
#[case::eos_no_track(vec![3])]
#[case::eos_short(vec![3, 1, 2])]
#[case::eos_extra(vec![3, 1, 0, 0, 0, 13, 9])]
fn malformed_bodies(#[case] body: Vec<u8>) {
    assert!(matches!(
        ControlMessage::decode(&body),
        Err(MediaError::DescriptorMalformed(_))
    ));
}

#[test]
fn trailing_bytes_and_bad_kind_and_utf8_rejected() {
    let mut body = ControlMessage::AcceptTracks(vec![video()])
        .encode()
        .unwrap();
    body.push(0);
    assert!(matches!(
        ControlMessage::decode(&body),
        Err(MediaError::DescriptorMalformed(
            "trailing bytes after track list"
        ))
    ));
    let mut body = ControlMessage::AcceptTracks(vec![video()])
        .encode()
        .unwrap();
    body[3] = 7;
    assert_eq!(
        ControlMessage::decode(&body),
        Err(MediaError::UnknownTrackKind(7))
    );
    let mut body = ControlMessage::AnnounceTracks(vec![audio()])
        .encode()
        .unwrap();
    body[18] = 0xFF;
    assert!(matches!(
        ControlMessage::decode(&body),
        Err(MediaError::DescriptorMalformed("name is not UTF-8"))
    ));
    let mut body = ControlMessage::AnnounceTracks(vec![audio()])
        .encode()
        .unwrap();
    body[4..8].copy_from_slice(&[0; 4]);
    assert!(matches!(
        ControlMessage::decode(&body),
        Err(MediaError::DescriptorMalformed("clock_rate must be > 0"))
    ));
    let mut name_cut = ControlMessage::AnnounceTracks(vec![audio()])
        .encode()
        .unwrap();
    name_cut.truncate(name_cut.len() - 1);
    assert!(matches!(
        ControlMessage::decode(&name_cut),
        Err(MediaError::DescriptorMalformed("name truncated"))
    ));
}
