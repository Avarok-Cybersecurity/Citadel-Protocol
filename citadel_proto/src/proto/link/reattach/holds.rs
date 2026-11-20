//! The server's held sessions, and the admission rule a reattach must pass. Pure: the caller
//! supplies the time and the proof check, so every refusal is reachable from a test.

use super::{Reattach, ReattachRefusal};
use crate::proto::link::{ManagedLinks, Millis};
use crate::proto::remote::Ticket;
use crate::proto::session_resume::ResumeToken;
use std::collections::HashMap;
use std::time::Duration;

struct Held {
    cid: u64,
    token: ResumeToken,
    incarnation: u64,
    /// When the path dropped; `None` while a path is attached.
    dropped_at: Option<Millis>,
    /// The highest attempt admitted for this connection. Kept across drops, so a frame admitted
    /// once can never be admitted again.
    last_attempt: Option<u64>,
}

/// Sessions whose path dropped, kept for `reattach_grace` (§5.2, Q2).
pub(crate) struct ReattachHolds {
    grace: Duration,
    held: HashMap<Ticket, Held>,
}

impl ReattachHolds {
    /// The grace is the node's `ManagedLinks::reattach_grace`: one setting, required, no default.
    pub(crate) fn new(links: &ManagedLinks) -> Self {
        Self {
            grace: links.reattach_grace(),
            held: HashMap::new(),
        }
    }

    /// The session's path dropped at `now`; keep it for the grace.
    pub(crate) fn hold(
        &mut self,
        connection_id: Ticket,
        cid: u64,
        token: ResumeToken,
        incarnation: u64,
        now: Millis,
    ) {
        let entry = self.held.entry(connection_id).or_insert(Held {
            cid,
            token,
            incarnation,
            dropped_at: None,
            last_attempt: None,
        });
        if entry.incarnation != incarnation {
            entry.last_attempt = None;
        }
        (entry.cid, entry.token, entry.incarnation) = (cid, token, incarnation);
        entry.dropped_at = Some(now);
    }

    /// The session ended for good (a disconnect, or a fresh seal replaced it).
    pub(crate) fn release(&mut self, connection_id: Ticket) {
        let _ = self.held.remove(&connection_id);
    }

    /// Ends every hold older than the grace at `now`; returns their CIDs, for the caller to end
    /// the sessions they held.
    pub(crate) fn expire(&mut self, now: Millis) -> Vec<u64> {
        let grace = self.grace;
        let mut ended = Vec::new();
        self.held.retain(|_, held| match held.dropped_at {
            Some(at) if now >= at.after(grace) => {
                ended.push(held.cid);
                false
            }
            _ => true,
        });
        ended
    }

    /// Admits `frame` at `now`, returning the held session's CID, or says why not. `proof_opens`
    /// opens the proof under that session's ratchet; it is asked only once the claim names a
    /// held session, inside its grace, with a fresh attempt.
    pub(crate) fn admit(
        &mut self,
        frame: &Reattach,
        now: Millis,
        proof_opens: impl FnOnce(u64) -> bool,
    ) -> Result<u64, ReattachRefusal> {
        let binding = frame.binding;
        let held = self
            .held
            .get_mut(&binding.connection_id)
            .filter(|held| held.incarnation == binding.incarnation)
            .filter(|held| held.token.same_as(&frame.resume_token))
            .ok_or(ReattachRefusal::NotHeld)?;
        let dropped_at = held.dropped_at.ok_or(ReattachRefusal::NotHeld)?;
        if now >= dropped_at.after(self.grace) {
            let _ = self.held.remove(&binding.connection_id);
            return Err(ReattachRefusal::GraceExpired);
        }
        if held
            .last_attempt
            .is_some_and(|last| binding.attempt <= last)
        {
            return Err(ReattachRefusal::StaleAttempt);
        }
        if !proof_opens(held.cid) {
            return Err(ReattachRefusal::ProofInvalid);
        }
        held.last_attempt = Some(binding.attempt);
        held.dropped_at = None;
        Ok(held.cid)
    }
}
