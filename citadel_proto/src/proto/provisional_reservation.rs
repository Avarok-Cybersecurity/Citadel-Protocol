//! A client's claim on a provisional key, held from the moment its connect is admitted until its
//! session is registered under that key.
//!
//! The admission check and the registration are separated by the transport connect, so without a
//! claim two connects for one account both pass the check, and the second's registration replaces
//! the first's session mid-handshake. The claim is given back on drop, so a connect that fails
//! before registering never blocks the next one.
//!
//! A claim names the ticket of the connect that holds it, so an aborted connect's claim can be
//! taken back at once (`CitadelSessionManager::abort_connect`), and the aborted connect's own
//! guard, dropped later, cannot remove the claim of the connect admitted after it.

use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::remote::Ticket;
use crate::proto::session_manager::{CitadelSessionManager, ProvisionalKey};
use citadel_crypt::ratchets::Ratchet;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

pub(crate) struct ProvisionalReservation<R: Ratchet, T: PlatformOps> {
    manager: CitadelSessionManager<R, T>,
    key: ProvisionalKey,
    ticket: Ticket,
}

impl<R: Ratchet, T: PlatformOps> ProvisionalReservation<R, T> {
    /// Called with the manager's state already borrowed as `claims`, so the check and the claim
    /// are one step. `None` if the key is already claimed.
    pub(crate) fn claim(
        claims: &mut HashMap<ProvisionalKey, Ticket>,
        manager: &CitadelSessionManager<R, T>,
        key: &ProvisionalKey,
        ticket: Ticket,
    ) -> Option<Self> {
        let Entry::Vacant(free) = claims.entry(key.clone()) else {
            return None;
        };
        let _ = free.insert(ticket);
        Some(Self {
            manager: manager.clone(),
            key: key.clone(),
            ticket,
        })
    }
}

impl<R: Ratchet, T: PlatformOps> Drop for ProvisionalReservation<R, T> {
    fn drop(&mut self) {
        let mut manager = inner_mut!(self.manager);
        if manager.provisional_reservations.get(&self.key) == Some(&self.ticket) {
            let _ = manager.provisional_reservations.remove(&self.key);
        }
    }
}
