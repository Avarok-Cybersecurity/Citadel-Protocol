use crate::error::MediaError;
use bytes::Bytes;

/// The media type carried by a track. Encoded in the high nibble of wire byte 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TrackKind {
    Audio = 0,
    Video = 1,
}

impl TrackKind {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Result<Self, MediaError> {
        match value {
            0 => Ok(Self::Audio),
            1 => Ok(Self::Video),
            other => Err(MediaError::UnknownTrackKind(other)),
        }
    }
}

/// Identifies one of up to 256 independent tracks within a media session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TrackId(pub u8);

impl TrackId {
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Per-frame flags. Encoded in the low nibble of wire byte 3; reserved bits are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameFlags(u8);

impl FrameFlags {
    pub const NONE: Self = Self(0);
    pub const KEYFRAME: Self = Self(0b0001);
    pub const DISCARDABLE: Self = Self(0b0010);
    const VALID_MASK: u8 = 0b0011;

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn from_bits(bits: u8) -> Result<Self, MediaError> {
        if bits & !Self::VALID_MASK != 0 {
            Err(MediaError::ReservedFlags(bits))
        } else {
            Ok(Self(bits))
        }
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn is_keyframe(self) -> bool {
        self.contains(Self::KEYFRAME)
    }

    pub const fn is_discardable(self) -> bool {
        self.contains(Self::DISCARDABLE)
    }
}

impl std::ops::BitOr for FrameFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// Logical frame metadata shared by every fragment of the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameHeader {
    pub track: TrackId,
    pub kind: TrackKind,
    pub sequence: u32,
    pub timestamp: u32,
    pub flags: FrameFlags,
}

/// A fully reassembled media frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaFrame {
    pub header: FrameHeader,
    pub payload: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_reject_reserved_bits() {
        assert_eq!(
            FrameFlags::from_bits(0b0100),
            Err(MediaError::ReservedFlags(4))
        );
        assert_eq!(
            FrameFlags::from_bits(0b1111),
            Err(MediaError::ReservedFlags(15))
        );
        let f = FrameFlags::from_bits(0b0011).unwrap();
        assert!(f.is_keyframe() && f.is_discardable());
        assert_eq!(FrameFlags::KEYFRAME | FrameFlags::DISCARDABLE, f);
        assert!(!FrameFlags::NONE.is_keyframe());
    }

    #[test]
    fn kind_roundtrip() {
        assert_eq!(TrackKind::from_u8(0), Ok(TrackKind::Audio));
        assert_eq!(TrackKind::from_u8(1), Ok(TrackKind::Video));
        assert_eq!(TrackKind::from_u8(2), Err(MediaError::UnknownTrackKind(2)));
        assert_eq!(TrackId(7).index(), 7);
    }
}
