//! The recovery lane: a device that holds no bundle for an account reaches it with the account's
//! recovery phrase.
//!
//! ```text
//! DO_REGISTER STAGE0 / STAGE1        the registration's own key exchange, unchanged
//! RECOVER_START      C→S  RecoverStart: a login start naming the phrase's key, and the device
//! RECOVER_CHALLENGE  S→C  an encapsulation to that key (a phrase-shaped decoy for any other)
//! RECOVER_PROOF      C→S  the tag, bound to the key exchange, the start and the challenge
//! RECOVER_DONE       S→C  the exchange's ratchet is now the account's only bundle
//! ```
//!
//! Everything after STAGE1 is sealed under the new ratchet. The server throttles and asks
//! admission before it looks the account up or encapsulates, refuses every failure alike, and on
//! success ends the account's live session and installs the ratchet, which revokes every other
//! device. The recovered device then signs in with the phrase, to a session that may manage the
//! account's credentials and nothing else. Both sides run it only with a node at or above
//! `RECOVERY_SINCE`.

pub(crate) mod client;
pub(crate) mod server;
pub(crate) mod state;

use crate::constants::{protocol_version_at_least, RECOVERY_SINCE};

/// Whether a server at `server_version` recovers accounts, challenges a phrase at sign-in, and
/// reads `SetPassword` and `RegenerateRecoveryPhrase`. An unknown version does not. A client
/// asks a server none of these unless it does.
pub(crate) fn server_recovers(server_version: Option<u32>) -> bool {
    protocol_version_at_least(server_version, RECOVERY_SINCE)
}
