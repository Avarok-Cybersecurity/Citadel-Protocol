//! The primary stream's framing: a `u32` big-endian length, then that many bytes of body.
//!
//! [`super::direct_frame_writer`] writes these frames; [`PrimaryFrameDecoder`] reads them. It reads
//! what tokio-util's `LengthDelimitedCodec` reads with the same settings, and its read buffer
//! grows with the bytes that arrive, a read-ahead at a time, rather than to a frame's declared
//! length.

use bytes::{Buf, BytesMut};
use citadel_io::tokio_util::codec::Decoder;
use std::io;

/// Bytes in a frame's length prefix.
pub(crate) const LEN_PREFIX_LEN: usize = 4;

/// The largest frame either end of a primary stream accepts. It is the bound the stream has
/// always had (unchanged, so nothing an existing peer sends is refused): large packets reach the
/// stream already chunked, so honest frames stay far below it.
pub const MAX_PRIMARY_FRAME_LEN: usize = 64 * 1024 * 1024;

/// The most the decoder reserves ahead of the bytes it has: 64 KiB, the largest TCP receive
/// window without window scaling, so one read can fill it and the buffer never holds more than a
/// window beyond what the peer has actually sent.
pub(crate) const READ_AHEAD: usize = 64 * 1024;

/// Reads length-prefixed frames of at most `max_frame_len` bytes.
#[derive(Clone, Copy, Debug)]
pub struct PrimaryFrameDecoder {
    max_frame_len: usize,
}

impl PrimaryFrameDecoder {
    pub fn new(max_frame_len: usize) -> Self {
        Self { max_frame_len }
    }
}

impl Decoder for PrimaryFrameDecoder {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        let Some(prefix) = src.get(..LEN_PREFIX_LEN) else {
            return Ok(None);
        };
        let declared = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
        if declared > self.max_frame_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "frame of {declared} bytes exceeds the {} byte maximum",
                    self.max_frame_len
                ),
            ));
        }
        let missing = (LEN_PREFIX_LEN + declared).saturating_sub(src.len());
        if missing > 0 {
            src.reserve(missing.min(READ_AHEAD));
            return Ok(None);
        }
        src.advance(LEN_PREFIX_LEN);
        Ok(Some(src.split_to(declared)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(body: &[u8]) -> BytesMut {
        let mut bytes = BytesMut::from(&(body.len() as u32).to_be_bytes()[..]);
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn it_reads_a_whole_frame_and_leaves_the_next() {
        let mut src = framed(b"hello");
        src.extend_from_slice(&framed(b"next"));
        let mut decoder = PrimaryFrameDecoder::new(16);
        assert_eq!(&decoder.decode(&mut src).unwrap().unwrap()[..], b"hello");
        assert_eq!(&decoder.decode(&mut src).unwrap().unwrap()[..], b"next");
        assert!(decoder.decode(&mut src).unwrap().is_none());
    }

    #[test]
    fn a_frame_above_the_maximum_is_refused() {
        let mut src = framed(&[0u8; 17]);
        let err = PrimaryFrameDecoder::new(16).decode(&mut src).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn an_incomplete_frame_reserves_at_most_a_read_ahead() {
        let mut src = BytesMut::from(&(u32::MAX).to_be_bytes()[..]);
        let mut decoder = PrimaryFrameDecoder::new(u32::MAX as usize);
        assert!(decoder.decode(&mut src).unwrap().is_none());
        assert!(src.capacity() <= LEN_PREFIX_LEN + READ_AHEAD);
    }
}
