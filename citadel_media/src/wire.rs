//! Single source of truth for the media datagram byte layout.
//!
//! Fragment header (20 bytes, big-endian):
//! `[0] version=1 | [1] msg_type | [2] track | [3] kind<<4 | flags |
//!  [4..8] frame_sequence u32 | [8..12] timestamp u32 | [12..16] total_len u32 |
//!  [16..18] frag_index u16 | [18..20] frag_count u16`
//!
//! Control message: `[0] version=1 | [1] msg_type=1 | [2..] TLV body`.
use crate::error::MediaError;
use crate::frame::{FrameFlags, FrameHeader, TrackId, TrackKind};

pub const WIRE_VERSION: u8 = 1;
pub const FRAGMENT_HEADER_LEN: usize = 20;
pub const CONTROL_HEADER_LEN: usize = 2;

pub const MSG_TYPE_FRAGMENT: u8 = 0;
pub const MSG_TYPE_CONTROL: u8 = 1;

/// Decoded fragment header; `frame` carries the per-frame metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    pub frame: FrameHeader,
    pub total_len: u32,
    pub frag_index: u16,
    pub frag_count: u16,
}

impl FragmentHeader {
    pub fn encode(&self) -> [u8; FRAGMENT_HEADER_LEN] {
        let mut out = [0u8; FRAGMENT_HEADER_LEN];
        out[0] = WIRE_VERSION;
        out[1] = MSG_TYPE_FRAGMENT;
        out[2] = self.frame.track.0;
        out[3] = (self.frame.kind.as_u8() << 4) | (self.frame.flags.bits() & 0x0F);
        out[4..8].copy_from_slice(&self.frame.sequence.to_be_bytes());
        out[8..12].copy_from_slice(&self.frame.timestamp.to_be_bytes());
        out[12..16].copy_from_slice(&self.total_len.to_be_bytes());
        out[16..18].copy_from_slice(&self.frag_index.to_be_bytes());
        out[18..20].copy_from_slice(&self.frag_count.to_be_bytes());
        out
    }

    /// Decodes a fragment header. The caller must already have checked version and msg_type.
    pub fn decode(bytes: &[u8]) -> Result<Self, MediaError> {
        if bytes.len() < FRAGMENT_HEADER_LEN {
            return Err(MediaError::HeaderTooShort {
                len: bytes.len(),
                need: FRAGMENT_HEADER_LEN,
            });
        }
        let kind = TrackKind::from_u8(bytes[3] >> 4)?;
        let flags = FrameFlags::from_bits(bytes[3] & 0x0F)?;
        let frag_index = u16::from_be_bytes([bytes[16], bytes[17]]);
        let frag_count = u16::from_be_bytes([bytes[18], bytes[19]]);
        if frag_count == 0 {
            return Err(MediaError::FragmentCountZero);
        }
        if frag_index >= frag_count {
            return Err(MediaError::FragmentIndexOutOfRange {
                index: frag_index,
                count: frag_count,
            });
        }
        Ok(Self {
            frame: FrameHeader {
                track: TrackId(bytes[2]),
                kind,
                sequence: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
                timestamp: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
                flags,
            },
            total_len: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            frag_index,
            frag_count,
        })
    }
}

/// A parsed datagram borrowing its payload from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireMessage<'a> {
    Fragment {
        header: FragmentHeader,
        payload: &'a [u8],
    },
    Control(&'a [u8]),
}

/// Parses a datagram: validates version, message type and header structure.
pub fn parse(datagram: &[u8]) -> Result<WireMessage<'_>, MediaError> {
    if datagram.len() < CONTROL_HEADER_LEN {
        return Err(MediaError::HeaderTooShort {
            len: datagram.len(),
            need: CONTROL_HEADER_LEN,
        });
    }
    if datagram[0] != WIRE_VERSION {
        return Err(MediaError::UnsupportedVersion(datagram[0]));
    }
    match datagram[1] {
        MSG_TYPE_FRAGMENT => {
            let header = FragmentHeader::decode(datagram)?;
            Ok(WireMessage::Fragment {
                header,
                payload: &datagram[FRAGMENT_HEADER_LEN..],
            })
        }
        MSG_TYPE_CONTROL => Ok(WireMessage::Control(&datagram[CONTROL_HEADER_LEN..])),
        other => Err(MediaError::UnknownMessageType(other)),
    }
}

/// Builds a control datagram: version + msg_type prefix followed by the TLV body.
pub fn encode_control(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONTROL_HEADER_LEN + body.len());
    out.push(WIRE_VERSION);
    out.push(MSG_TYPE_CONTROL);
    out.extend_from_slice(body);
    out
}
