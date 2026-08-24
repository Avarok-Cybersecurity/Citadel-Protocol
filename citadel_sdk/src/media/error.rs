//! `MediaError` → `NetworkError` mapping. A `From` impl is impossible here
//! (orphan rule: both types are foreign), so the conversion is a function plus
//! a result-extension trait.
use citadel_io::ErrorCode;
use citadel_media::MediaError;
use citadel_proto::prelude::NetworkError;

/// Maps a [`MediaError`] onto the registry: config errors become
/// `MediaConfigInvalid`, everything else `MediaFrameRejected`.
pub fn from_media_error(err: MediaError) -> NetworkError {
    match err {
        MediaError::InvalidConfig(_) => citadel_io::error!(ErrorCode::MediaConfigInvalid, err),
        _ => citadel_io::error!(ErrorCode::MediaFrameRejected, err),
    }
}

/// `Result<T, MediaError>` → `Result<T, NetworkError>`.
pub trait MediaResultExt<T> {
    fn net(self) -> Result<T, NetworkError>;
}

impl<T> MediaResultExt<T> for Result<T, MediaError> {
    fn net(self) -> Result<T, NetworkError> {
        self.map_err(from_media_error)
    }
}
