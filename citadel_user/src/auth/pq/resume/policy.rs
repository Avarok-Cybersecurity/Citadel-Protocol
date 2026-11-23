//! How long a server lets a resume credential live.

use crate::misc::AccountError;
use citadel_io::{error, ErrorCode};
use std::time::Duration;

/// A server's limit on resume credentials. A server with none issues and honours none.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResumePolicy {
    max_lifetime_ms: u64,
}

impl ResumePolicy {
    /// `max_lifetime` is the longest a credential may live, whatever a client asks for. There is
    /// no default: a server that wants none sets no policy.
    pub fn new(max_lifetime: Duration) -> Result<Self, AccountError> {
        let max_lifetime_ms = u64::try_from(max_lifetime.as_millis()).ok();
        match max_lifetime_ms.filter(|ms| *ms >= 1_000) {
            Some(max_lifetime_ms) => Ok(Self { max_lifetime_ms }),
            None => Err(error!(
                ErrorCode::PqSignInUnavailable,
                "a resume credential's maximum lifetime is at least one second"
            )),
        }
    }

    pub fn max_lifetime_ms(&self) -> u64 {
        self.max_lifetime_ms
    }

    /// As a challenge tells it to the client, in whole seconds.
    pub fn max_lifetime_s(&self) -> u64 {
        self.max_lifetime_ms / 1_000
    }

    /// The lifetime granted to a request for `asked_s` seconds: never more than the maximum.
    pub fn granted_ms(&self, asked_s: u64) -> u64 {
        asked_s.saturating_mul(1_000).min(self.max_lifetime_ms)
    }

    /// When a grant issued at `issued_at_utc` to live until `valid_until_utc` stops being
    /// honoured: its own expiry, or this policy's maximum if that has since become shorter.
    pub fn honoured_until(&self, issued_at_utc: u64, valid_until_utc: u64) -> u64 {
        valid_until_utc.min(issued_at_utc.saturating_add(self.max_lifetime_ms))
    }
}
