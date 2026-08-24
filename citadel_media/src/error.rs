use std::fmt;

/// Errors produced by the media framing, reassembly and jitter layers.
#[derive(Debug, PartialEq)]
pub enum MediaError {
    InvalidConfig(&'static str),
    FrameTooLarge { len: usize, max: usize },
    HeaderTooShort { len: usize, need: usize },
    UnsupportedVersion(u8),
    UnknownMessageType(u8),
    FragmentIndexOutOfRange { index: u16, count: u16 },
    FragmentCountZero,
    TotalLenMismatch { expected: u32, actual: u32 },
    PayloadLenMismatch { expected: usize, actual: usize },
    TrackMismatch { expected: u8, actual: u8 },
    FrameHeaderMismatch,
    ReservedFlags(u8),
    UnknownTrackKind(u8),
    DescriptorMalformed(&'static str),
    Demux(DemuxError),
}

impl fmt::Display for MediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(what) => write!(f, "invalid media config: {what}"),
            Self::FrameTooLarge { len, max } => {
                write!(f, "frame of {len} bytes exceeds maximum of {max}")
            }
            Self::HeaderTooShort { len, need } => {
                write!(f, "header too short: {len} bytes, need {need}")
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported wire version {v}"),
            Self::UnknownMessageType(t) => write!(f, "unknown message type {t}"),
            Self::FragmentIndexOutOfRange { index, count } => {
                write!(f, "fragment index {index} out of range for count {count}")
            }
            Self::FragmentCountZero => write!(f, "fragment count is zero"),
            Self::TotalLenMismatch { expected, actual } => {
                write!(f, "total_len mismatch: expected {expected}, got {actual}")
            }
            Self::PayloadLenMismatch { expected, actual } => {
                write!(
                    f,
                    "payload length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::TrackMismatch { expected, actual } => {
                write!(f, "track mismatch: expected {expected}, got {actual}")
            }
            Self::FrameHeaderMismatch => {
                write!(
                    f,
                    "fragment header disagrees with earlier fragments of the frame"
                )
            }
            Self::ReservedFlags(bits) => write!(f, "reserved flag bits set: {bits:#04x}"),
            Self::UnknownTrackKind(k) => write!(f, "unknown track kind {k}"),
            Self::DescriptorMalformed(what) => write!(f, "malformed descriptor: {what}"),
            Self::Demux(e) => write!(f, "demux error: {e}"),
        }
    }
}

impl std::error::Error for MediaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Demux(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DemuxError> for MediaError {
    fn from(e: DemuxError) -> Self {
        Self::Demux(e)
    }
}

/// Errors produced by the WAV/IVF container readers and writers.
#[derive(Debug)]
pub enum DemuxError {
    Io(std::io::Error),
    BadMagic(&'static str),
    Truncated(&'static str),
    Unsupported(&'static str),
    Malformed(&'static str),
}

impl fmt::Display for DemuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::BadMagic(what) => write!(f, "bad magic: {what}"),
            Self::Truncated(what) => write!(f, "truncated input: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported format: {what}"),
            Self::Malformed(what) => write!(f, "malformed container: {what}"),
        }
    }
}

impl std::error::Error for DemuxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DemuxError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl PartialEq for DemuxError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(a), Self::Io(b)) => a.kind() == b.kind(),
            (Self::BadMagic(a), Self::BadMagic(b))
            | (Self::Truncated(a), Self::Truncated(b))
            | (Self::Unsupported(a), Self::Unsupported(b))
            | (Self::Malformed(a), Self::Malformed(b)) => a == b,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn display_and_source() {
        let e = MediaError::FrameTooLarge { len: 5, max: 4 };
        assert_eq!(e.to_string(), "frame of 5 bytes exceeds maximum of 4");
        assert!(e.source().is_none());
        let d = MediaError::from(DemuxError::BadMagic("RIFF"));
        assert_eq!(d.to_string(), "demux error: bad magic: RIFF");
        assert!(d.source().is_some());
        let io = DemuxError::from(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        assert!(io.source().is_some());
        assert_eq!(io, DemuxError::Io(std::io::ErrorKind::UnexpectedEof.into()));
    }
}
