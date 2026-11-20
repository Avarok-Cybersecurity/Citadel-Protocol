//! Reattach: a new path, the same seal (`ROBUST-CONNECTION-MANAGER.md` §5.2).
//!
//! After a drop, both ends keep the sealed session for the server's `reattach_grace`. The
//! client presents a [`Reattach`] in the first packet of a fresh path; the server checks it
//! against the session it holds ([`ReattachHolds`]) and answers [`Reattached`] or
//! [`ReattachRefused`]. Servers verify, clients compute: the client seals the proof under its
//! live ratchet ([`seal_proof`]); the server only opens it ([`proof_opens`]).
//!
//! Gated by [`LINK_REATTACH_SINCE`]: a peer below it, or of unknown version, is never sent a
//! frame, and the manager plans a fresh seal as before.

mod holds;
mod proof;

use crate::constants::{protocol_version_at_least, LINK_REATTACH_SINCE};
use crate::proto::remote::Ticket;
use crate::proto::session_resume::ResumeToken;
use serde::{Deserialize, Serialize};

pub(crate) use holds::ReattachHolds;
pub(crate) use proof::{proof_opens, seal_proof};

/// Whether a peer at `adjacent_version` understands the reattach frames.
pub(crate) fn peer_may_reattach(adjacent_version: Option<u32>) -> bool {
    protocol_version_at_least(adjacent_version, LINK_REATTACH_SINCE)
}

/// What a reattach proof binds: the connection it claims, which incarnation of it, and which try.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReattachBinding {
    /// The held session's connection id (its kernel ticket).
    pub connection_id: Ticket,
    /// The incarnation the client sealed with: a session re-established from scratch is another.
    pub incarnation: u64,
    /// Strictly increasing per connection, so a captured frame cannot be replayed.
    pub attempt: u64,
}

/// The client's claim, in the first packet of a fresh path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reattach {
    pub binding: ReattachBinding,
    /// The token the server issued this session at connect: names a held session of the account.
    pub resume_token: ResumeToken,
    /// [`seal_proof`] of `binding` under the session's live ratchet.
    pub proof: Vec<u8>,
}

/// The server took the new path under the held session.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reattached {
    /// The ratchet version the server holds, so the client resumes on it.
    pub latest_version: u32,
}

/// Why a reattach was refused. The client then seals afresh on the path it already opened; it
/// never dials again for a refusal.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReattachRefusal {
    /// No held session matches the frame's connection, incarnation and token. One answer for all
    /// three, so a refusal does not say which part of a guess was right.
    NotHeld,
    /// The session was held, but for longer than the server's `reattach_grace`.
    GraceExpired,
    /// The attempt is not above the last one this connection reattached with.
    StaleAttempt,
    /// The proof does not open under the held session's ratchet.
    ProofInvalid,
}

/// The server's refusal.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReattachRefused {
    pub reason: ReattachRefusal,
}

#[cfg(test)]
mod tests;
