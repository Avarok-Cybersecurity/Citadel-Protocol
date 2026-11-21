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
//! account's credentials and nothing else. Every node this one takes part with runs it
//! (`RECOVERY_SINCE`, `version_gate`).

pub(crate) mod client;
pub(crate) mod server;
pub(crate) mod state;
