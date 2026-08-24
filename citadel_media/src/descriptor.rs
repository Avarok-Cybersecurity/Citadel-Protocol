//! Track descriptors and control messages with a hand-rolled TLV encoding.
//!
//! Control body: `[msg_tag u8] [count u8] (descriptor)*` for track lists, or
//! `[msg_tag u8] [track u8] [frames_sent u32]` for EndOfStream. Descriptor (big-endian):
//! `track u8 | kind u8 | clock_rate u32 | codec [u8;4] | channels u8 | width u16 |
//!  height u16 | name_len u8 | name[name_len]`.
use crate::error::MediaError;
use crate::frame::{TrackId, TrackKind};

pub const MAX_TRACK_NAME_LEN: usize = 64;
const DESCRIPTOR_FIXED_LEN: usize = 1 + 1 + 4 + 4 + 1 + 2 + 2 + 1;

const TAG_ANNOUNCE: u8 = 1;
const TAG_ACCEPT: u8 = 2;
const TAG_END_OF_STREAM: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaTrackDescriptor {
    pub track: TrackId,
    pub kind: TrackKind,
    pub clock_rate: u32,
    pub codec: [u8; 4],
    pub channels: u8,
    pub width: u16,
    pub height: u16,
    pub name: String,
}

impl MediaTrackDescriptor {
    pub fn validate(&self) -> Result<(), MediaError> {
        if self.name.len() > MAX_TRACK_NAME_LEN {
            return Err(MediaError::DescriptorMalformed("name exceeds 64 bytes"));
        }
        if self.clock_rate == 0 {
            return Err(MediaError::DescriptorMalformed("clock_rate must be > 0"));
        }
        Ok(())
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), MediaError> {
        self.validate()?;
        out.push(self.track.0);
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.clock_rate.to_be_bytes());
        out.extend_from_slice(&self.codec);
        out.push(self.channels);
        out.extend_from_slice(&self.width.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.push(self.name.len() as u8);
        out.extend_from_slice(self.name.as_bytes());
        Ok(())
    }

    /// Decodes one descriptor from the front of `buf`; returns it and the remaining bytes.
    fn decode_from(buf: &[u8]) -> Result<(Self, &[u8]), MediaError> {
        if buf.len() < DESCRIPTOR_FIXED_LEN {
            return Err(MediaError::DescriptorMalformed("descriptor truncated"));
        }
        let name_len = buf[15] as usize;
        if name_len > MAX_TRACK_NAME_LEN {
            return Err(MediaError::DescriptorMalformed("name exceeds 64 bytes"));
        }
        let end = DESCRIPTOR_FIXED_LEN + name_len;
        if buf.len() < end {
            return Err(MediaError::DescriptorMalformed("name truncated"));
        }
        let name = std::str::from_utf8(&buf[DESCRIPTOR_FIXED_LEN..end])
            .map_err(|_| MediaError::DescriptorMalformed("name is not UTF-8"))?
            .to_owned();
        let d = Self {
            track: TrackId(buf[0]),
            kind: TrackKind::from_u8(buf[1])?,
            clock_rate: u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]),
            codec: [buf[6], buf[7], buf[8], buf[9]],
            channels: buf[10],
            width: u16::from_be_bytes([buf[11], buf[12]]),
            height: u16::from_be_bytes([buf[13], buf[14]]),
            name,
        };
        d.validate()?;
        Ok((d, &buf[end..]))
    }
}

/// Session-level control messages carried in `msg_type = 1` datagrams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    AnnounceTracks(Vec<MediaTrackDescriptor>),
    AcceptTracks(Vec<MediaTrackDescriptor>),
    /// `track` is finished; frames `0..frames_sent` were sent (the sender's
    /// next sequence for the track), letting the receiver drain in-flight
    /// frames that race the control channel before surfacing the end.
    EndOfStream {
        track: TrackId,
        frames_sent: u32,
    },
}

impl ControlMessage {
    /// Encodes the TLV body (without the 2-byte wire prefix; see `wire::encode_control`).
    pub fn encode(&self) -> Result<Vec<u8>, MediaError> {
        let mut out = Vec::new();
        match self {
            Self::AnnounceTracks(list) => Self::encode_list(TAG_ANNOUNCE, list, &mut out)?,
            Self::AcceptTracks(list) => Self::encode_list(TAG_ACCEPT, list, &mut out)?,
            Self::EndOfStream { track, frames_sent } => {
                out.push(TAG_END_OF_STREAM);
                out.push(track.0);
                out.extend_from_slice(&frames_sent.to_be_bytes());
            }
        }
        Ok(out)
    }

    fn encode_list(
        tag: u8,
        list: &[MediaTrackDescriptor],
        out: &mut Vec<u8>,
    ) -> Result<(), MediaError> {
        let count = u8::try_from(list.len())
            .map_err(|_| MediaError::DescriptorMalformed("more than 255 tracks"))?;
        out.push(tag);
        out.push(count);
        for d in list {
            d.encode_into(out)?;
        }
        Ok(())
    }

    pub fn decode(body: &[u8]) -> Result<Self, MediaError> {
        let (&tag, rest) = body
            .split_first()
            .ok_or(MediaError::DescriptorMalformed("empty control body"))?;
        match tag {
            TAG_ANNOUNCE => Ok(Self::AnnounceTracks(Self::decode_list(rest)?)),
            TAG_ACCEPT => Ok(Self::AcceptTracks(Self::decode_list(rest)?)),
            TAG_END_OF_STREAM => match rest {
                [track, a, b, c, d] => Ok(Self::EndOfStream {
                    track: TrackId(*track),
                    frames_sent: u32::from_be_bytes([*a, *b, *c, *d]),
                }),
                _ => Err(MediaError::DescriptorMalformed(
                    "end-of-stream body must be exactly track byte + frames_sent u32",
                )),
            },
            _ => Err(MediaError::DescriptorMalformed("unknown control tag")),
        }
    }

    fn decode_list(mut rest: &[u8]) -> Result<Vec<MediaTrackDescriptor>, MediaError> {
        let (&count, tail) = rest
            .split_first()
            .ok_or(MediaError::DescriptorMalformed("missing track count"))?;
        rest = tail;
        let mut list = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (d, tail) = MediaTrackDescriptor::decode_from(rest)?;
            list.push(d);
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(MediaError::DescriptorMalformed(
                "trailing bytes after track list",
            ));
        }
        Ok(list)
    }
}
