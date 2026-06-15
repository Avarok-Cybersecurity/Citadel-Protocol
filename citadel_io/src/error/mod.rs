//! The workspace-wide canonical error type.
//!
//! [`NetworkError`] replaces the per-crate error enums that used to live in `citadel_proto`,
//! `citadel_crypt`, `citadel_user`, `citadel_wire`, `citadel_types`, `netbeam`, `async_ip`, and
//! `firebase-rtdb`. It is a small, `Clone`able value: a 2-byte [`ErrorCode`] (the stable error code +
//! canonical message) plus an optional **boxed** per-occurrence `detail` string. Variants that never
//! carry dynamic context construct with `detail == None` and never allocate.
//!
//! Size: `size_of::<NetworkError>()` is asserted by the unit tests below; the `code` itself is exactly
//! 2 bytes, satisfying the "stable numeric code, up to 65_536 values" goal.

mod code;
mod construct;

pub use code::ErrorCode;

/// The single error type used across the entire Citadel workspace.
///
/// Construct via the typed helpers ([`NetworkError::generic`], [`NetworkError::timeout`],
/// [`NetworkError::encrypt`], …) rather than building the struct directly, so the `detail`
/// invariant (boxed, only present when there is real per-occurrence context) is upheld.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.render())]
pub struct NetworkError {
    /// The stable error code (also selects the canonical message).
    pub code: ErrorCode,
    /// Optional, boxed per-occurrence context appended to the canonical message.
    detail: Option<Box<str>>,
}

impl NetworkError {
    /// Construct from a code with no dynamic detail (never allocates).
    pub const fn bare(code: ErrorCode) -> Self {
        Self { code, detail: None }
    }

    /// Construct from a code plus per-occurrence detail (boxed).
    pub fn coded<T: Into<String>>(code: ErrorCode, detail: T) -> Self {
        Self {
            code,
            detail: Some(detail.into().into_boxed_str()),
        }
    }

    /// The stable numeric error code (the [`ErrorCode`] `#[repr(u16)]` discriminant).
    pub const fn code(&self) -> u16 {
        self.code.as_u16()
    }

    /// The per-occurrence detail, if any (without the canonical message prefix).
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// The full display message (canonical message, plus `": <detail>"` when present).
    fn render(&self) -> String {
        match &self.detail {
            Some(detail) => format!("{}: {detail}", self.code.message()),
            None => self.code.message().to_string(),
        }
    }

    /// Consume into the full display message. Mirrors the old `into_string()` helpers.
    pub fn into_string(self) -> String {
        self.render()
    }
}

impl From<std::io::Error> for NetworkError {
    fn from(err: std::io::Error) -> Self {
        Self::coded(ErrorCode::Io, err.to_string())
    }
}

#[cfg(not(target_family = "wasm"))]
impl<T> From<crate::tokio::sync::mpsc::error::SendError<T>> for NetworkError {
    fn from(err: crate::tokio::sync::mpsc::error::SendError<T>) -> Self {
        Self::coded(ErrorCode::ChannelSend, err.to_string())
    }
}

impl From<NetworkError> for std::io::Error {
    fn from(err: NetworkError) -> Self {
        std::io::Error::other(err.into_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The code is exactly 2 bytes (the "up to 65_536 stable codes" goal), and the whole error stays
    /// pointer-sized + the code. `Option<Box<str>>` is a 16-byte fat pointer (null-niche'd), so the
    /// struct is 24 bytes; documented here so a regression (e.g. inlining a `String`) is caught.
    #[test]
    fn sizes_are_minimal() {
        assert_eq!(
            core::mem::size_of::<ErrorCode>(),
            2,
            "ErrorCode must stay 2 bytes"
        );
        assert!(
            core::mem::size_of::<NetworkError>() <= 24,
            "NetworkError grew beyond 24 bytes: {}",
            core::mem::size_of::<NetworkError>()
        );
    }

    #[test]
    fn display_with_and_without_detail() {
        let bare = NetworkError::bare(ErrorCode::ProperShutdown);
        assert_eq!(bare.to_string(), "The session was shut down properly");
        assert_eq!(bare.code(), ErrorCode::ProperShutdown as u16);
        assert_eq!(bare.detail(), None);

        let detailed = NetworkError::generic("boom");
        assert_eq!(detailed.to_string(), "An error occurred: boom");
        assert_eq!(detailed.detail(), Some("boom"));
    }

    #[test]
    fn codes_are_stable_and_distinct() {
        // A few anchors — renumbering these would break wire/log compatibility.
        assert_eq!(ErrorCode::Generic as u16, 0);
        assert_eq!(ErrorCode::Io as u16, 9);
    }
}
