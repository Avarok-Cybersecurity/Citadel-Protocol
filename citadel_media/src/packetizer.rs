use crate::config::MediaConfig;
use crate::error::MediaError;
use crate::frame::{FrameFlags, FrameHeader, TrackId, TrackKind};
use crate::wire::{FragmentHeader, FRAGMENT_HEADER_LEN};
use bytes::{BufMut, Bytes, BytesMut};

/// One outgoing datagram: encoded header plus a zero-copy slice of the frame payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentOut {
    pub header: [u8; FRAGMENT_HEADER_LEN],
    pub payload: Bytes,
}

impl FragmentOut {
    pub const fn wire_len(&self) -> usize {
        FRAGMENT_HEADER_LEN + self.payload.len()
    }

    /// Appends header + payload to `dst` (the only copy in the send path).
    pub fn write_into(&self, dst: &mut BytesMut) {
        dst.reserve(self.wire_len());
        dst.put_slice(&self.header);
        dst.put_slice(&self.payload);
    }
}

/// Iterator over the fragments of one frame. Slices the source `Bytes` without copying.
#[derive(Debug, Clone)]
pub struct Fragments {
    frame: FrameHeader,
    payload: Bytes,
    max_fragment_payload: usize,
    frag_count: u16,
    next_index: u16,
}

impl Fragments {
    pub const fn frag_count(&self) -> u16 {
        self.frag_count
    }

    pub const fn frame(&self) -> &FrameHeader {
        &self.frame
    }
}

impl Iterator for Fragments {
    type Item = FragmentOut;

    fn next(&mut self) -> Option<FragmentOut> {
        if self.next_index >= self.frag_count {
            return None;
        }
        let index = self.next_index;
        self.next_index += 1;
        let start = index as usize * self.max_fragment_payload;
        let end = (start + self.max_fragment_payload).min(self.payload.len());
        let header = FragmentHeader {
            frame: self.frame,
            total_len: self.payload.len() as u32,
            frag_index: index,
            frag_count: self.frag_count,
        };
        Some(FragmentOut {
            header: header.encode(),
            payload: self.payload.slice(start..end),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = (self.frag_count - self.next_index) as usize;
        (rem, Some(rem))
    }
}

impl ExactSizeIterator for Fragments {}

/// Splits frames into wire fragments, assigning a wrapping per-track sequence number.
#[derive(Debug)]
pub struct Packetizer {
    config: MediaConfig,
    next_sequence: [u32; 256],
}

impl Packetizer {
    pub fn new(config: MediaConfig) -> Result<Self, MediaError> {
        config.validate()?;
        Ok(Self {
            config,
            next_sequence: [0; 256],
        })
    }

    pub const fn config(&self) -> &MediaConfig {
        &self.config
    }

    pub const fn next_sequence(&self, track: TrackId) -> u32 {
        self.next_sequence[track.index()]
    }

    /// Sets the next sequence a track will emit (e.g. to resume or to test wrap-around).
    pub fn set_next_sequence(&mut self, track: TrackId, sequence: u32) {
        self.next_sequence[track.index()] = sequence;
    }

    pub fn packetize(
        &mut self,
        track: TrackId,
        kind: TrackKind,
        timestamp: u32,
        flags: FrameFlags,
        payload: Bytes,
    ) -> Result<Fragments, MediaError> {
        if payload.len() > self.config.max_frame_bytes {
            return Err(MediaError::FrameTooLarge {
                len: payload.len(),
                max: self.config.max_frame_bytes,
            });
        }
        let frag_count = self.config.fragment_count_for(payload.len());
        let frag_count = u16::try_from(frag_count).map_err(|_| MediaError::FrameTooLarge {
            len: payload.len(),
            max: self.config.max_frame_bytes,
        })?;
        let slot = &mut self.next_sequence[track.index()];
        let sequence = *slot;
        *slot = slot.wrapping_add(1);
        Ok(Fragments {
            frame: FrameHeader {
                track,
                kind,
                sequence,
                timestamp,
                flags,
            },
            payload,
            max_fragment_payload: self.config.max_fragment_payload,
            frag_count,
            next_index: 0,
        })
    }
}
