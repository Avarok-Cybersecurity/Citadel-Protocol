//! Container demuxers operating only on caller-injected `std::io::Read`/`Write`.
mod ivf;
mod wav;

pub use ivf::{vp8_is_keyframe, IvfFrame, IvfHeader, IvfReader, IvfWriter, IVF_HEADER_LEN};
pub use wav::{WavFormat, WavReader};

pub(crate) fn read_exact_or<R: std::io::Read>(
    reader: &mut R,
    buf: &mut [u8],
    what: &'static str,
) -> Result<(), crate::error::DemuxError> {
    reader.read_exact(buf).map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => crate::error::DemuxError::Truncated(what),
        _ => crate::error::DemuxError::Io(e),
    })
}
