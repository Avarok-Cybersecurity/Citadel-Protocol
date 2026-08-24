use super::read_exact_or;
use crate::error::DemuxError;
use bytes::{Bytes, BytesMut};
use std::io::{Read, Write};

pub const IVF_HEADER_LEN: usize = 32;
const IVF_FRAME_HEADER_LEN: usize = 12;
const IVF_VERSION: u16 = 0;

/// The 32-byte IVF file header (all fields little-endian on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IvfHeader {
    pub fourcc: [u8; 4],
    pub width: u16,
    pub height: u16,
    pub timebase_den: u32,
    pub timebase_num: u32,
    pub frame_count: u32,
}

impl IvfHeader {
    pub fn encode(&self) -> [u8; IVF_HEADER_LEN] {
        let mut out = [0u8; IVF_HEADER_LEN];
        out[0..4].copy_from_slice(b"DKIF");
        out[4..6].copy_from_slice(&IVF_VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&(IVF_HEADER_LEN as u16).to_le_bytes());
        out[8..12].copy_from_slice(&self.fourcc);
        out[12..14].copy_from_slice(&self.width.to_le_bytes());
        out[14..16].copy_from_slice(&self.height.to_le_bytes());
        out[16..20].copy_from_slice(&self.timebase_den.to_le_bytes());
        out[20..24].copy_from_slice(&self.timebase_num.to_le_bytes());
        out[24..28].copy_from_slice(&self.frame_count.to_le_bytes());
        out
    }

    pub fn decode(b: &[u8; IVF_HEADER_LEN]) -> Result<Self, DemuxError> {
        if &b[0..4] != b"DKIF" {
            return Err(DemuxError::BadMagic("expected DKIF"));
        }
        if u16::from_le_bytes([b[4], b[5]]) != IVF_VERSION {
            return Err(DemuxError::Unsupported("IVF version must be 0"));
        }
        if u16::from_le_bytes([b[6], b[7]]) as usize != IVF_HEADER_LEN {
            return Err(DemuxError::Malformed("IVF header_size must be 32"));
        }
        Ok(Self {
            fourcc: [b[8], b[9], b[10], b[11]],
            width: u16::from_le_bytes([b[12], b[13]]),
            height: u16::from_le_bytes([b[14], b[15]]),
            timebase_den: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            timebase_num: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
            frame_count: u32::from_le_bytes([b[24], b[25], b[26], b[27]]),
        })
    }

    /// Microseconds for presentation timestamp `pts` in this header's timebase.
    pub const fn pts_to_micros(&self, pts: u64) -> Option<u64> {
        if self.timebase_den == 0 {
            return None;
        }
        Some(
            pts.saturating_mul(self.timebase_num as u64)
                .saturating_mul(1_000_000)
                / self.timebase_den as u64,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IvfFrame {
    pub pts: u64,
    pub data: Bytes,
}

/// Reads IVF frames from an injected `Read`.
#[derive(Debug)]
pub struct IvfReader<R: Read> {
    reader: R,
    header: IvfHeader,
    max_frame_bytes: usize,
}

impl<R: Read> IvfReader<R> {
    /// `max_frame_bytes` bounds each frame allocation so a corrupt size field cannot OOM.
    pub fn new(mut reader: R, max_frame_bytes: usize) -> Result<Self, DemuxError> {
        if max_frame_bytes == 0 {
            return Err(DemuxError::Malformed("max_frame_bytes must be > 0"));
        }
        let mut raw = [0u8; IVF_HEADER_LEN];
        read_exact_or(&mut reader, &mut raw, "IVF header")?;
        Ok(Self {
            reader,
            header: IvfHeader::decode(&raw)?,
            max_frame_bytes,
        })
    }

    pub const fn header(&self) -> &IvfHeader {
        &self.header
    }

    /// `Ok(None)` at a clean end of stream; a partial frame header or body is `Truncated`.
    pub fn next_frame(&mut self, scratch: &mut BytesMut) -> Result<Option<IvfFrame>, DemuxError> {
        let mut fh = [0u8; IVF_FRAME_HEADER_LEN];
        match self.reader.read(&mut fh[..1])? {
            0 => return Ok(None),
            _ => read_exact_or(&mut self.reader, &mut fh[1..], "IVF frame header")?,
        }
        let size = u32::from_le_bytes([fh[0], fh[1], fh[2], fh[3]]) as usize;
        if size > self.max_frame_bytes {
            return Err(DemuxError::Malformed("IVF frame exceeds max_frame_bytes"));
        }
        let pts = u64::from_le_bytes([fh[4], fh[5], fh[6], fh[7], fh[8], fh[9], fh[10], fh[11]]);
        scratch.resize(size, 0);
        read_exact_or(&mut self.reader, &mut scratch[..size], "IVF frame body")?;
        Ok(Some(IvfFrame {
            pts,
            data: scratch.split_to(size).freeze(),
        }))
    }
}

/// Writes IVF frames to an injected `Write`.
#[derive(Debug)]
pub struct IvfWriter<W: Write> {
    writer: W,
    frames_written: u32,
}

impl<W: Write> IvfWriter<W> {
    pub fn new(mut writer: W, header: &IvfHeader) -> Result<Self, DemuxError> {
        writer.write_all(&header.encode())?;
        Ok(Self {
            writer,
            frames_written: 0,
        })
    }

    pub fn write_frame(&mut self, pts: u64, data: &[u8]) -> Result<(), DemuxError> {
        let size =
            u32::try_from(data.len()).map_err(|_| DemuxError::Malformed("frame exceeds u32"))?;
        let mut fh = [0u8; IVF_FRAME_HEADER_LEN];
        fh[0..4].copy_from_slice(&size.to_le_bytes());
        fh[4..12].copy_from_slice(&pts.to_le_bytes());
        self.writer.write_all(&fh)?;
        self.writer.write_all(data)?;
        self.frames_written += 1;
        Ok(())
    }

    pub const fn frames_written(&self) -> u32 {
        self.frames_written
    }

    pub fn finish(mut self) -> Result<W, DemuxError> {
        self.writer.flush()?;
        Ok(self.writer)
    }
}

/// VP8 frame tag: bit 0 of the first byte is 0 for a key frame.
pub const fn vp8_is_keyframe(frame: &[u8]) -> bool {
    match frame.first() {
        Some(&b) => b & 1 == 0,
        None => false,
    }
}
