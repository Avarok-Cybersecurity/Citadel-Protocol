//! What a server tells a client whose SYN it does not go on with.
//!
//! The client has proved nothing yet, so the reply is the same whatever the reason: an account
//! this server does not hold reads exactly like a SYN that does not open under the account's
//! keys. The reason is kept for the server's own log.

use crate::error::NetworkError;
use citadel_io::{error, ErrorCode};

/// Why a server does not go on with a SYN.
pub(crate) enum SynRefusal {
    /// The SYN names an account this server does not hold.
    UnknownAccount(u64),
    /// The SYN does not open under the account's keys.
    Unauthenticated(NetworkError),
}

impl SynRefusal {
    /// The reason the refusal carries to the client: one, whatever the cause.
    pub(crate) fn reply(&self) -> String {
        error!(ErrorCode::PreconnectRefused).into_string()
    }
}

/// The reason, for the server's log.
impl std::fmt::Display for SynRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAccount(cid) => write!(f, "CID {cid} is not registered to this node"),
            Self::Unauthenticated(err) => write!(f, "the SYN did not authenticate: {err:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_account_and_an_unauthenticated_syn_read_alike() {
        let unknown = SynRefusal::UnknownAccount(0x5eed).reply();
        let unauthenticated =
            SynRefusal::Unauthenticated(NetworkError::msg("Unable to validate initial packet"))
                .reply();
        assert_eq!(unknown, unauthenticated);
        assert!(!unknown.contains(&0x5eed_u64.to_string()), "{unknown}");
    }
}
