use super::read_exact_or;
use crate::error::DemuxError;
use bytes::{Bytes, BytesMut};
use std::io::Read;

const PCM_FORMAT_TAG: u16 = 1;
const MICROS_PER_SECOND: u64 = 1_000_000;

/// The `fmt ` chunk of a PCM WAV file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WavFormat {
    pub channels: u16,
    pub sample_rate: u32,
    pub bits_per_sample: u16,
    pub block_align: u16,
}

impl WavFormat {
    /// Bytes covering `frame_micros` of audio, rounded down to whole sample blocks.
    pub const fn bytes_per_frame(&self, frame_micros: u64) -> usize {
        let samples = (self.sample_rate as u64 * frame_micros) / MICROS_PER_SECOND;
        (samples * self.block_align as u64) as usize
    }
}

/// Streams PCM sample blocks out of a RIFF/WAVE container.
#[derive(Debug)]
pub struct WavReader<R: Read> {
    reader: R,
    format: WavFormat,
    data_remaining: u64,
}

impl<R: Read> WavReader<R> {
    pub fn new(mut reader: R) -> Result<Self, DemuxError> {
        let mut riff = [0u8; 12];
        read_exact_or(&mut reader, &mut riff, "RIFF header")?;
        if &riff[0..4] != b"RIFF" {
            return Err(DemuxError::BadMagic("expected RIFF"));
        }
        if &riff[8..12] != b"WAVE" {
            return Err(DemuxError::BadMagic("expected WAVE"));
        }
        let mut format: Option<WavFormat> = None;
        loop {
            let mut chunk = [0u8; 8];
            read_exact_or(&mut reader, &mut chunk, "chunk header")?;
            let size = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            match &chunk[0..4] {
                b"fmt " => format = Some(Self::parse_fmt(&mut reader, size)?),
                b"data" => {
                    let format = format.ok_or(DemuxError::Malformed("data before fmt"))?;
                    return Ok(Self {
                        reader,
                        format,
                        data_remaining: size as u64,
                    });
                }
                _ => Self::skip(&mut reader, size as u64 + (size as u64 & 1))?,
            }
        }
    }

    fn parse_fmt(reader: &mut R, size: u32) -> Result<WavFormat, DemuxError> {
        if size < 16 {
            return Err(DemuxError::Malformed("fmt chunk shorter than 16 bytes"));
        }
        let mut fmt = [0u8; 16];
        read_exact_or(reader, &mut fmt, "fmt chunk")?;
        Self::skip(reader, size as u64 - 16 + (size as u64 & 1))?;
        let tag = u16::from_le_bytes([fmt[0], fmt[1]]);
        if tag != PCM_FORMAT_TAG {
            return Err(DemuxError::Unsupported(
                "only PCM (format tag 1) is supported",
            ));
        }
        let format = WavFormat {
            channels: u16::from_le_bytes([fmt[2], fmt[3]]),
            sample_rate: u32::from_le_bytes([fmt[4], fmt[5], fmt[6], fmt[7]]),
            block_align: u16::from_le_bytes([fmt[12], fmt[13]]),
            bits_per_sample: u16::from_le_bytes([fmt[14], fmt[15]]),
        };
        if format.channels == 0 || format.sample_rate == 0 || format.block_align == 0 {
            return Err(DemuxError::Malformed(
                "zero channels, sample rate or block align",
            ));
        }
        let expected_align = format.channels * format.bits_per_sample.div_ceil(8);
        if format.block_align != expected_align {
            return Err(DemuxError::Malformed(
                "block_align inconsistent with channels/bits",
            ));
        }
        Ok(format)
    }

    fn skip(reader: &mut R, mut n: u64) -> Result<(), DemuxError> {
        let mut scratch = [0u8; 256];
        while n > 0 {
            let take = (n as usize).min(scratch.len());
            read_exact_or(reader, &mut scratch[..take], "skipped chunk")?;
            n -= take as u64;
        }
        Ok(())
    }

    pub const fn format(&self) -> &WavFormat {
        &self.format
    }

    pub const fn data_remaining(&self) -> u64 {
        self.data_remaining
    }

    pub const fn bytes_per_frame(&self, frame_micros: u64) -> usize {
        self.format.bytes_per_frame(frame_micros)
    }

    /// Reads the next `frame_micros` of sample blocks into `scratch` and splits them off.
    /// The final chunk may be shorter; `Ok(None)` once the data chunk is exhausted.
    pub fn next_chunk(
        &mut self,
        frame_micros: u64,
        scratch: &mut BytesMut,
    ) -> Result<Option<Bytes>, DemuxError> {
        if self.data_remaining == 0 {
            return Ok(None);
        }
        let want = self.bytes_per_frame(frame_micros);
        if want == 0 {
            return Err(DemuxError::Malformed(
                "frame_micros shorter than one sample block",
            ));
        }
        let take = (want as u64).min(self.data_remaining) as usize;
        let aligned = take - (take % self.format.block_align as usize);
        if aligned == 0 {
            return Err(DemuxError::Truncated("data chunk ends mid sample block"));
        }
        scratch.resize(aligned, 0);
        read_exact_or(&mut self.reader, &mut scratch[..aligned], "data chunk")?;
        self.data_remaining -= aligned as u64;
        Ok(Some(scratch.split_to(aligned).freeze()))
    }
}
