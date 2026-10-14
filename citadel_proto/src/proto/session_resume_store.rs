//! Server side: each admitted session's resume token, kept in the account backend so the
//! admission grace outlives the server process.
//!
//! [`EndedSessions`](crate::proto::session_resume::EndedSessions) and the held sessions live in
//! memory, so a server restart (a Durable Object redeployed or reset, an eviction, a crash)
//! forgot every token it had issued. Every client the restart cut off then reconnected inside
//! its grace and was asked the admission check (Turnstile) again, which an automatic reconnect
//! cannot show: one deploy signed every connected user out.
//!
//! So each admitted session's token is written through the backend's byte map (as
//! `group_persistence` keeps the group registry), and again with its end time when the session
//! ends. The in-memory state stays the authority while the process runs; this is its durable
//! copy, consulted only when memory does not recognise a token. A record that never got its end
//! time was live when its server stopped, so the stop is when it ended, and that was no later
//! than this node started: such a record counts only within the grace of this node's start.
//!
//! Only a SHA3-256 digest of each token is stored, and like the token itself it is consulted
//! only after a login has fully authenticated, to skip the admission check; it admits nothing.
//!
//! Layout: `(cid, 0, "session_resume", <token digest hex>)` → empty while the session is live,
//! else the end time in ms since the Unix epoch (big-endian `u64`). A CID's records are all
//! replaced when a new session for it is admitted, so each token exempts one reconnect at most
//! (an end recorded just after that may write its own token back, still bounded by its grace).

use crate::proto::session_resume::ResumeToken;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use citadel_user::backend::PersistenceHandler;
use citadel_user::misc::AccountError;
use sha3::{Digest, Sha3_256};

const RESUME: &str = "session_resume";
const NO_PEER: u64 = 0;

/// What the backend says of a presented token.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum StoredResume {
    /// Issued to a session that was live when its server stopped.
    LiveAtStop,
    /// Issued to a session that ended at this many ms since the Unix epoch.
    EndedAtMs(u64),
}

impl StoredResume {
    fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        match bytes.len() {
            0 => Ok(Self::LiveAtStop),
            8 => Ok(Self::EndedAtMs(u64::from_be_bytes(
                bytes.try_into().expect("length checked"),
            ))),
            n => Err(AccountError::msg(format!(
                "a stored resume record is {n} bytes, neither 0 nor 8"
            ))),
        }
    }

    /// Whether this record still exempts a login at `now` (wall clock, ms since the epoch, and
    /// this node's clock), on a node that started at `node_started`.
    pub(crate) fn within_grace(
        self,
        grace: Duration,
        now_ms: u64,
        node_started: Instant,
        now: Instant,
    ) -> bool {
        match self {
            Self::LiveAtStop => node_started
                .checked_add(grace)
                .is_some_and(|expires| now < expires),
            Self::EndedAtMs(ended) => {
                let grace_ms = u64::try_from(grace.as_millis()).unwrap_or(u64::MAX);
                now_ms < ended.saturating_add(grace_ms)
            }
        }
    }
}

fn sub_key(token: &ResumeToken) -> String {
    format!("{:x}", Sha3_256::digest(token.to_bytes()))
}

/// Wall-clock time in ms since the Unix epoch.
pub(crate) fn now_ms() -> Result<u64, AccountError> {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| AccountError::msg(format!("the clock is before the Unix epoch: {err}")))?;
    u64::try_from(since.as_millis())
        .map_err(|_| AccountError::msg("the clock is past what a u64 of ms holds"))
}

/// A session for `cid` was admitted with `issued`: it replaces whatever `cid` had.
pub(crate) async fn on_admitted<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    cid: u64,
    issued: &ResumeToken,
) -> Result<(), AccountError> {
    pers.remove_byte_map_values_by_key(cid, NO_PEER, RESUME)
        .await?;
    pers.store_byte_map_value(cid, NO_PEER, RESUME, &sub_key(issued), Vec::new())
        .await
        .map(|_| ())
}

/// `cid`'s session, issued `issued`, ended at `ended_ms`.
pub(crate) async fn on_ended<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    cid: u64,
    issued: &ResumeToken,
    ended_ms: u64,
) -> Result<(), AccountError> {
    let record = ended_ms.to_be_bytes().to_vec();
    pers.store_byte_map_value(cid, NO_PEER, RESUME, &sub_key(issued), record)
        .await
        .map(|_| ())
}

/// The record of `presented` among `cid`'s, if there is one.
pub(crate) async fn lookup<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    cid: u64,
    presented: &ResumeToken,
) -> Result<Option<StoredResume>, AccountError> {
    pers.get_byte_map_value(cid, NO_PEER, RESUME, &sub_key(presented))
        .await?
        .as_deref()
        .map(StoredResume::decode)
        .transpose()
}

#[cfg(test)]
#[path = "session_resume_store_tests.rs"]
mod tests;
