//! A reconnecting client replaces the session the server still holds for it, and only its own.
//!
//! When a client's link dies without a FIN or RST reaching the server (an IP change, a cell
//! handover, sleep), the server keeps the old session until its keep-alive expires, up to an
//! hour by default, and refuses every login for the account in the meantime. A login with
//! `force_login` displaces it (see `admit_authenticated_login`), but an automatic reconnect
//! cannot force without risking a live session that belongs to someone else.
//!
//! So the server hands each admitted client a random [`ResumeToken`] inside the encrypted
//! connect SUCCESS, and the client presents it in its next connect STAGE0, also encrypted. At
//! STAGE0, after the credentials have been checked, a held session whose token matches is
//! this same client's dead session and is displaced exactly as `force_login` would displace
//! it. Any other held session is left alone and the login is refused as before.
//!
//! A held session also accepts the token presented by the login that created it. If that
//! login's SUCCESS was lost on the way back, the client still holds the older token, and its
//! next attempt must still count as its own.
//!
//! The server also remembers each ended session's token for the admission policy's
//! `resume_grace` ([`EndedSessions`]): a reconnect after a clean close or a keep-alive expiry
//! finds no held session to recognise it, and without this would be asked the admission check
//! (Turnstile) again. That memory exempts from admission only; it displaces nothing.
//!
//! Both sides exchange tokens only with a node at [`SESSION_RESUME_SINCE`] or later. Older
//! nodes see neither field (trailing bytes are ignored), and a newer node reads none from them.
use crate::constants::{protocol_version_at_least, SESSION_RESUME_SINCE};
use citadel_io::time::{Duration, Instant};
use citadel_io::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

const RESUME_TOKEN_LEN: usize = 32;

/// Identifies one admitted session to the client it was issued to. It grants nothing by itself:
/// it is only consulted after a login has fully authenticated.
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ResumeToken([u8; RESUME_TOKEN_LEN]);

impl ResumeToken {
    /// A fresh token from the platform CSPRNG: `thread_rng` on std, the `getrandom`-backed
    /// `WasmRng` on wasm (as `group_cgka::fresh_secret`).
    pub(crate) fn generate() -> Self {
        let mut bytes = [0u8; RESUME_TOKEN_LEN];
        #[cfg(not(target_family = "wasm"))]
        let mut rng = citadel_io::thread_rng();
        #[cfg(target_family = "wasm")]
        let mut rng = citadel_io::ThreadRng;
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// As carried inside a post-quantum `LoginStart`, which `citadel_user` defines.
    pub(crate) fn from_bytes(bytes: [u8; RESUME_TOKEN_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn to_bytes(self) -> [u8; RESUME_TOKEN_LEN] {
        self.0
    }

    /// Constant-time equality.
    fn same_as(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
    }
}

impl Debug for ResumeToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResumeToken(..)")
    }
}

/// Server side: which presented tokens show a login to be the held session's own client.
#[derive(Copy, Clone, Default, Debug)]
pub(crate) struct HeldSessionResume {
    issued: Option<ResumeToken>,
    resumed_from: Option<ResumeToken>,
}

impl HeldSessionResume {
    /// The record for a session admitted with `issued`, by a login that presented `presented`.
    pub(crate) fn admitted(issued: ResumeToken, presented: Option<ResumeToken>) -> Self {
        Self {
            issued: Some(issued),
            resumed_from: presented,
        }
    }

    /// The token this session was issued, if it was admitted.
    pub(crate) fn issued(&self) -> Option<ResumeToken> {
        self.issued
    }

    pub(crate) fn is_own_client(&self, presented: Option<&ResumeToken>) -> bool {
        let Some(presented) = presented else {
            return false;
        };
        [self.issued, self.resumed_from]
            .iter()
            .flatten()
            .any(|held| held.same_as(presented))
    }
}

/// Why a fully authenticated login may displace the session the server holds for its account.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Displacement {
    /// The client asked to displace whatever the server holds.
    Forced,
    /// The held session is this client's own, and dead from the client's side.
    OwnSession,
}

/// Whether, and why, a login that has passed STAGE0 may displace `held`. `None` means refuse.
pub(crate) fn displacement(
    force_login: bool,
    held: &HeldSessionResume,
    presented: Option<&ResumeToken>,
) -> Option<Displacement> {
    if force_login {
        Some(Displacement::Forced)
    } else if held.is_own_client(presented) {
        Some(Displacement::OwnSession)
    } else {
        None
    }
}

/// `token` if the adjacent node at `adjacent_version` takes part in session resumption, else
/// `None`. Applied to what is sent to it and to what is read from it.
pub(crate) fn exchanged_with(
    adjacent_version: u32,
    token: Option<ResumeToken>,
) -> Option<ResumeToken> {
    token.filter(|_| protocol_version_at_least(Some(adjacent_version), SESSION_RESUME_SINCE))
}

/// Whether a SYN for an account whose session the server holds is refused before it can
/// authenticate. A client that might hold a resume token gets as far as STAGE0, where the
/// token is checked; the held session is not touched before then either way.
pub(crate) fn refused_at_syn(adjacent_version: u32, force_login: bool) -> bool {
    !force_login && !protocol_version_at_least(Some(adjacent_version), SESSION_RESUME_SINCE)
}

/// Client side: the token each account's latest session was issued, kept after it ends.
#[derive(Default)]
pub(crate) struct ResumeTokens {
    by_cid: HashMap<u64, ResumeToken>,
}

impl ResumeTokens {
    /// Records what a connect SUCCESS for `cid` carried. `None` (a server that issues none)
    /// forgets any older token, which that server would not recognise.
    pub(crate) fn on_connect_success(&mut self, cid: u64, issued: Option<ResumeToken>) {
        match issued {
            Some(token) => {
                let _ = self.by_cid.insert(cid, token);
            }
            None => {
                let _ = self.by_cid.remove(&cid);
            }
        }
    }

    pub(crate) fn for_cid(&self, cid: u64) -> Option<ResumeToken> {
        self.by_cid.get(&cid).copied()
    }
}

/// Server side: the token each CID's last ended session was issued, until it expires.
///
/// Only the ended session's OWN token is kept (not the one it resumed from), and a CID's
/// entry goes as soon as any new session for it is admitted, so each token exempts one
/// reconnect at most. One entry per CID, and every write drops the expired ones.
#[derive(Default)]
pub(crate) struct EndedSessions {
    by_cid: HashMap<u64, (ResumeToken, Instant)>,
}

impl EndedSessions {
    /// `cid`'s session, issued `issued`, ended at `now`; its token counts for `grace`.
    pub(crate) fn on_session_end(
        &mut self,
        cid: u64,
        issued: ResumeToken,
        now: Instant,
        grace: Duration,
    ) {
        self.by_cid.retain(|_, (_, expires)| *expires > now);
        if let Some(expires) = now.checked_add(grace).filter(|expires| *expires > now) {
            let _ = self.by_cid.insert(cid, (issued, expires));
        }
    }

    /// A session for `cid` was admitted: whatever ended before it is spent.
    pub(crate) fn on_session_admitted(&mut self, cid: u64) {
        let _ = self.by_cid.remove(&cid);
    }

    /// Whether `presented`, at `now`, is the unexpired token of `cid`'s last ended session.
    pub(crate) fn recognises(&self, cid: u64, presented: &ResumeToken, now: Instant) -> bool {
        self.by_cid
            .get(&cid)
            .is_some_and(|(token, expires)| now < *expires && token.same_as(presented))
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_cid.len()
    }
}

#[cfg(test)]
#[path = "session_resume_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "session_resume_ended_tests.rs"]
mod ended_tests;
