//! The per-peer key material a session keeps for its P2P connections: the session password each
//! connection was set up with, and the ratchet of each ended connection, kept for
//! [`STALE_P2P_RATCHET_TTL`] so packets already in flight still open.
//!
//! Every entry carries a [`CountedHold`], so the node's
//! [`SessionFootprint`](crate::proto::session_ledger::SessionFootprint) counts exactly what is held.

use crate::constants::GROUP_EXPIRE_TIME_MS;
use crate::proto::remote::Ticket;
use crate::proto::session_ledger::{Counted, CountedHold, SessionLedger};
use citadel_types::crypto::PreSharedKey;
use std::collections::HashMap;
use std::time::Duration;

/// How long an ended P2P connection's ratchet is kept. A packet still in flight when the
/// connection ended arrives within moments; one group window is far longer, and any group that
/// stopped receiving for that long is discarded anyway.
pub(crate) const STALE_P2P_RATCHET_TTL: Duration = GROUP_EXPIRE_TIME_MS;

struct StaleRatchet<R> {
    ratchet: R,
    /// The connection the ratchet belonged to, so an expiry never removes a later one's.
    connection_id: Ticket,
    _hold: CountedHold,
}

/// Generic over the ratchet only to store it; nothing here reads it.
pub(crate) struct PeerKeys<R> {
    ledger: SessionLedger,
    passwords: HashMap<u64, (PreSharedKey, CountedHold)>,
    stale_ratchets: HashMap<u64, StaleRatchet<R>>,
}

impl<R> PeerKeys<R> {
    pub(crate) fn new(ledger: SessionLedger) -> Self {
        Self {
            ledger,
            passwords: HashMap::new(),
            stale_ratchets: HashMap::new(),
        }
    }

    pub(crate) fn store_password(&mut self, peer_cid: u64, password: PreSharedKey) {
        let hold = self.ledger.count(Counted::SessionPassword);
        let _ = self.passwords.insert(peer_cid, (password, hold));
    }

    pub(crate) fn password(&self, peer_cid: u64) -> Option<&PreSharedKey> {
        self.passwords.get(&peer_cid).map(|(password, _)| password)
    }

    pub(crate) fn remove_password(&mut self, peer_cid: u64) {
        let _ = self.passwords.remove(&peer_cid);
    }

    /// Keeps the ratchet of the ended connection `connection_id` with `peer_cid`, replacing any
    /// older one: see [`Self::expire_stale_ratchet`].
    pub(crate) fn keep_stale_ratchet(&mut self, peer_cid: u64, ratchet: R, connection_id: Ticket) {
        let stale = StaleRatchet {
            ratchet,
            connection_id,
            _hold: self.ledger.count(Counted::StaleP2pRatchet),
        };
        let _ = self.stale_ratchets.insert(peer_cid, stale);
    }

    pub(crate) fn stale_ratchet(&self, peer_cid: u64) -> Option<&R> {
        self.stale_ratchets
            .get(&peer_cid)
            .map(|stale| &stale.ratchet)
    }

    pub(crate) fn forget_stale_ratchet(&mut self, peer_cid: u64) {
        let _ = self.stale_ratchets.remove(&peer_cid);
    }

    /// Drops the stale ratchet of connection `connection_id` with `peer_cid`, if it is still the
    /// one kept. Returns whether it was.
    pub(crate) fn expire_stale_ratchet(&mut self, peer_cid: u64, connection_id: Ticket) -> bool {
        let current = self
            .stale_ratchets
            .get(&peer_cid)
            .is_some_and(|stale| stale.connection_id == connection_id);
        if current {
            self.forget_stale_ratchet(peer_cid);
        }
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_expiry_removes_only_the_connection_it_was_set_for() {
        let ledger = SessionLedger::default();
        let mut keys = PeerKeys::<&str>::new(ledger.clone());
        keys.keep_stale_ratchet(5, "first", Ticket(1));
        keys.keep_stale_ratchet(5, "second", Ticket(2));
        assert_eq!(ledger.counted(Counted::StaleP2pRatchet), 1);
        assert!(!keys.expire_stale_ratchet(5, Ticket(1)));
        assert_eq!(keys.stale_ratchet(5), Some(&"second"));
        assert!(keys.expire_stale_ratchet(5, Ticket(2)));
        assert!(keys.stale_ratchet(5).is_none());
        assert_eq!(ledger.counted(Counted::StaleP2pRatchet), 0);
    }

    #[test]
    fn a_removed_password_is_no_longer_counted() {
        let ledger = SessionLedger::default();
        let mut keys = PeerKeys::<&str>::new(ledger.clone());
        keys.store_password(5, PreSharedKey::default());
        keys.store_password(5, PreSharedKey::default());
        assert_eq!(ledger.counted(Counted::SessionPassword), 1);
        keys.remove_password(5);
        assert!(keys.password(5).is_none());
        assert_eq!(ledger.counted(Counted::SessionPassword), 0);
    }
}
