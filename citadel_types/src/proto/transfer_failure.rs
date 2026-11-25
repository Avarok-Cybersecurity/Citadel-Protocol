//! Why an object transfer ended without completing, by its stable error code.

use citadel_io::NetworkError;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
#[cfg(feature = "typescript")]
use ts_rs::TS;

/// A transfer's failure as the code of the [`citadel_io::ErrorCode`] that ended it and the
/// message that error rendered, so a reader can tell one failure from another by code rather
/// than by text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TransferFailure {
    /// The `citadel_io::ErrorCode` discriminant.
    pub code: u16,
    /// The error's rendered message.
    pub message: String,
}

impl TransferFailure {
    /// The error this failure names, rebuilt with its code.
    pub fn into_error(self) -> NetworkError {
        NetworkError::from_wire(self.code, self.message)
    }
}

impl From<&NetworkError> for TransferFailure {
    fn from(err: &NetworkError) -> Self {
        Self {
            code: err.code_u16(),
            message: err.to_string(),
        }
    }
}

impl Display for TransferFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code {})", self.message, self.code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::{error, ErrorCode};

    #[test]
    fn a_failure_keeps_its_code_across_the_round_trip() {
        let err = error!(ErrorCode::FileTransferStalled, 7u64);
        let failure = TransferFailure::from(&err);
        assert_eq!(failure.code, ErrorCode::FileTransferStalled.as_u16());
        assert_eq!(failure.message, err.to_string());
        let rebuilt = failure.into_error();
        assert_eq!(rebuilt.code(), ErrorCode::FileTransferStalled);
        assert_eq!(rebuilt.to_string(), err.to_string());
    }
}
