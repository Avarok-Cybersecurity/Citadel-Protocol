use bytes::BytesMut;
use citadel_media::demux::{vp8_is_keyframe, IvfHeader, IvfReader, IvfWriter, WavReader};
use citadel_media::DemuxError;
use std::io::Cursor;

fn wav(format_tag: u16, channels: u16, rate: u32, bits: u16, data: &[u8], extra: bool) -> Vec<u8> {
    let align = channels * bits / 8;
    let mut f = Vec::new();
    f.extend_from_slice(b"RIFF");
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(b"WAVE");
    if extra {
        f.extend_from_slice(b"LIST");
        f.extend_from_slice(&3u32.to_le_bytes());
        f.extend_from_slice(&[1, 2, 3, 0]);
    }
    f.extend_from_slice(b"fmt ");
    f.extend_from_slice(&16u32.to_le_bytes());
    f.extend_from_slice(&format_tag.to_le_bytes());
    f.extend_from_slice(&channels.to_le_bytes());
    f.extend_from_slice(&rate.to_le_bytes());
    f.extend_from_slice(&(rate * align as u32).to_le_bytes());
    f.extend_from_slice(&align.to_le_bytes());
    f.extend_from_slice(&bits.to_le_bytes());
    f.extend_from_slice(b"data");
    f.extend_from_slice(&(data.len() as u32).to_le_bytes());
    f.extend_from_slice(data);
    f
}

#[test]
fn wav_20ms_at_48k_stereo_16bit_is_3840_bytes() {
    let data: Vec<u8> = (0..3840 * 2 + 400).map(|i| i as u8).collect();
    let mut r = WavReader::new(Cursor::new(wav(1, 2, 48_000, 16, &data, true))).unwrap();
    assert_eq!(r.format().channels, 2);
    assert_eq!(r.format().sample_rate, 48_000);
    assert_eq!(r.format().block_align, 4);
    assert_eq!(r.bytes_per_frame(20_000), 3840);
    let mut scratch = BytesMut::new();
    let a = r.next_chunk(20_000, &mut scratch).unwrap().unwrap();
    assert_eq!(a.len(), 3840);
    assert_eq!(&a[..], &data[..3840]);
    let b = r.next_chunk(20_000, &mut scratch).unwrap().unwrap();
    assert_eq!(&b[..], &data[3840..7680]);
    let tail = r.next_chunk(20_000, &mut scratch).unwrap().unwrap();
    assert_eq!(tail.len(), 400);
    assert_eq!(r.data_remaining(), 0);
    assert!(r.next_chunk(20_000, &mut scratch).unwrap().is_none());
}

#[test]
fn wav_negatives() {
    let ok = wav(1, 1, 8000, 8, &[1, 2, 3, 4], false);
    let mut magic = ok.clone();
    magic[0] = b'X';
    assert_eq!(
        WavReader::new(Cursor::new(magic)).unwrap_err(),
        DemuxError::BadMagic("expected RIFF")
    );
    let mut wave = ok.clone();
    wave[8] = b'X';
    assert_eq!(
        WavReader::new(Cursor::new(wave)).unwrap_err(),
        DemuxError::BadMagic("expected WAVE")
    );
    assert!(matches!(
        WavReader::new(Cursor::new(&ok[..10])).unwrap_err(),
        DemuxError::Truncated(_)
    ));
    assert!(matches!(
        WavReader::new(Cursor::new(&ok[..20])).unwrap_err(),
        DemuxError::Truncated(_)
    ));
    assert_eq!(
        WavReader::new(Cursor::new(wav(3, 1, 8000, 32, &[], false))).unwrap_err(),
        DemuxError::Unsupported("only PCM (format tag 1) is supported")
    );
    let mut r = WavReader::new(Cursor::new(&ok[..ok.len() - 2])).unwrap();
    let mut scratch = BytesMut::new();
    assert!(matches!(
        r.next_chunk(1_000_000, &mut scratch).unwrap_err(),
        DemuxError::Truncated(_)
    ));
    let mut r = WavReader::new(Cursor::new(ok)).unwrap();
    assert!(matches!(
        r.next_chunk(1, &mut scratch).unwrap_err(),
        DemuxError::Malformed(_)
    ));
}

fn header() -> IvfHeader {
    IvfHeader {
        fourcc: *b"VP80",
        width: 352,
        height: 288,
        timebase_den: 30,
        timebase_num: 1,
        frame_count: 2,
    }
}

#[test]
fn ivf_writer_reader_roundtrip() {
    let mut w = IvfWriter::new(Vec::new(), &header()).unwrap();
    w.write_frame(0, &[0x10, 1, 2, 3]).unwrap();
    w.write_frame(1, &[0x11, 9]).unwrap();
    assert_eq!(w.frames_written(), 2);
    let bytes = w.finish().unwrap();
    assert_eq!(bytes.len(), 32 + 12 + 4 + 12 + 2);
    assert_eq!(&bytes[..4], b"DKIF");
    assert_eq!(&bytes[6..8], &32u16.to_le_bytes());
    assert_eq!(&bytes[32..36], &4u32.to_le_bytes());
    assert_eq!(&bytes[36..44], &0u64.to_le_bytes());

    let mut r = IvfReader::new(Cursor::new(bytes), 1 << 16).unwrap();
    assert_eq!(r.header(), &header());
    assert_eq!(r.header().pts_to_micros(3), Some(100_000));
    let mut scratch = BytesMut::new();
    let f0 = r.next_frame(&mut scratch).unwrap().unwrap();
    assert_eq!((f0.pts, &f0.data[..]), (0, &[0x10, 1, 2, 3][..]));
    assert!(vp8_is_keyframe(&f0.data));
    let f1 = r.next_frame(&mut scratch).unwrap().unwrap();
    assert_eq!((f1.pts, &f1.data[..]), (1, &[0x11, 9][..]));
    assert!(!vp8_is_keyframe(&f1.data));
    assert!(!vp8_is_keyframe(&[]));
    assert!(r.next_frame(&mut scratch).unwrap().is_none());
}

#[test]
fn ivf_negatives() {
    let mut w = IvfWriter::new(Vec::new(), &header()).unwrap();
    w.write_frame(0, &[0; 10]).unwrap();
    let ok = w.finish().unwrap();
    let mut magic = ok.clone();
    magic[1] = b'X';
    assert_eq!(
        IvfReader::new(Cursor::new(magic), 100).unwrap_err(),
        DemuxError::BadMagic("expected DKIF")
    );
    assert!(matches!(
        IvfReader::new(Cursor::new(&ok[..20]), 100).unwrap_err(),
        DemuxError::Truncated("IVF header")
    ));
    let mut scratch = BytesMut::new();
    let mut r = IvfReader::new(Cursor::new(&ok[..40]), 100).unwrap();
    assert!(matches!(
        r.next_frame(&mut scratch).unwrap_err(),
        DemuxError::Truncated("IVF frame header")
    ));
    let mut r = IvfReader::new(Cursor::new(&ok[..50]), 100).unwrap();
    assert!(matches!(
        r.next_frame(&mut scratch).unwrap_err(),
        DemuxError::Truncated("IVF frame body")
    ));
    let mut r = IvfReader::new(Cursor::new(ok.clone()), 9).unwrap();
    assert!(matches!(
        r.next_frame(&mut scratch).unwrap_err(),
        DemuxError::Malformed(_)
    ));
    assert!(IvfReader::new(Cursor::new(ok), 0).is_err());
}
