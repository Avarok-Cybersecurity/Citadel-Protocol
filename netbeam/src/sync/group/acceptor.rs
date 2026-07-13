//! The per-member consensus voter: a timerless two-transition Paxos acceptor.
//! All lock semantics live in [`crate::sync::group::ops::apply`] at the proposer;
//! the acceptor only orders proposals. Quorum intersection over acceptors is the
//! entire safety argument.

use crate::sync::group::record::LockRecord;
use crate::sync::group::wire::Ballot;
use crate::sync::group::LockId;
use serde::{Deserialize, Serialize};

/// Durable acceptor state. With the default [`EphemeralAcceptorStore`] the group is
/// safe under CRASH-STOP failures only: a voter that restarts with amnesia could
/// re-promise below an earlier promise and break quorum intersection. Consumers that
/// need voters to survive restart must persist this state via a durable
/// [`AcceptorStateStore`] (write-before-reply).
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedAcceptor {
    pub promised: Option<Ballot>,
    pub accepted: Option<(Ballot, LockRecord)>,
}

/// Reply to a `Prepare`.
#[derive(Clone, Debug)]
pub enum PrepareReply {
    Promise {
        accepted: Option<(Ballot, LockRecord)>,
    },
    Nack {
        promised: Ballot,
    },
}

/// Reply to an `Accept`.
#[derive(Clone, Debug)]
pub enum AcceptReply {
    Accepted,
    Nack { promised: Ballot },
}

/// The pure acceptor. `on_prepare`/`on_accept` are the only two transitions.
#[derive(Default, Clone, Debug)]
pub struct Acceptor {
    state: PersistedAcceptor,
}

impl Acceptor {
    pub fn from_persisted(state: PersistedAcceptor) -> Self {
        Self { state }
    }

    pub fn state(&self) -> &PersistedAcceptor {
        &self.state
    }

    pub fn on_prepare(&mut self, ballot: Ballot) -> PrepareReply {
        match self.state.promised {
            Some(promised) if ballot <= promised => PrepareReply::Nack { promised },
            _ => {
                self.state.promised = Some(ballot);
                PrepareReply::Promise {
                    accepted: self.state.accepted.clone(),
                }
            }
        }
    }

    pub fn on_accept(&mut self, ballot: Ballot, record: LockRecord) -> AcceptReply {
        match self.state.promised {
            Some(promised) if ballot < promised => AcceptReply::Nack { promised },
            _ => {
                self.state.promised = Some(ballot);
                self.state.accepted = Some((ballot, record));
                AcceptReply::Accepted
            }
        }
    }

    /// Non-linearizable read of the highest accepted record (a hint only; every
    /// decision that matters re-validates through a CAS round).
    pub fn read_hint(&self) -> Option<(Ballot, LockRecord)> {
        self.state.accepted.clone()
    }
}

/// Persistence hook for acceptor state. Implementations must make `save` durable
/// BEFORE the acceptor's reply is sent to preserve promise monotonicity across
/// restarts. The in-memory [`EphemeralAcceptorStore`] declares, by its name, that
/// restarts are NOT survivable (crash-stop model).
pub trait AcceptorStateStore: Send + Sync + 'static {
    fn load(&self, lock: LockId) -> Option<PersistedAcceptor>;
    fn save(&self, lock: LockId, state: &PersistedAcceptor);
}

/// In-memory store: voters are safe under crash-stop (a crashed member must not
/// rejoin as a voter). The explicit name is the API-level warning.
#[derive(Default)]
pub struct EphemeralAcceptorStore {
    states: citadel_io::RwLock<std::collections::HashMap<LockId, PersistedAcceptor>>,
}

impl AcceptorStateStore for EphemeralAcceptorStore {
    fn load(&self, lock: LockId) -> Option<PersistedAcceptor> {
        self.states.read().get(&lock).cloned()
    }

    fn save(&self, lock: LockId, state: &PersistedAcceptor) {
        let _ = self.states.write().insert(lock, state.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::group::MemberId;

    fn ballot(counter: u64, member: u64) -> Ballot {
        Ballot {
            counter,
            proposer: MemberId(member),
        }
    }

    #[test]
    fn promise_ordering() {
        let mut acc = Acceptor::default();
        assert!(matches!(
            acc.on_prepare(ballot(2, 1)),
            PrepareReply::Promise { .. }
        ));
        // lower and equal ballots are refused
        assert!(matches!(
            acc.on_prepare(ballot(1, 9)),
            PrepareReply::Nack { .. }
        ));
        assert!(matches!(
            acc.on_prepare(ballot(2, 1)),
            PrepareReply::Nack { .. }
        ));
        // higher counter or same counter from higher member id wins
        assert!(matches!(
            acc.on_prepare(ballot(2, 2)),
            PrepareReply::Promise { .. }
        ));
    }

    #[test]
    fn accept_below_promise_rejected_but_repromote_allowed() {
        let mut acc = Acceptor::default();
        let rec = LockRecord::initial(vec![1]);
        acc.on_prepare(ballot(5, 1));
        assert!(matches!(
            acc.on_accept(ballot(4, 9), rec.clone()),
            AcceptReply::Nack { .. }
        ));
        // accept at exactly the promised ballot succeeds
        assert!(matches!(
            acc.on_accept(ballot(5, 1), rec.clone()),
            AcceptReply::Accepted
        ));
        // a *higher* accept also succeeds (functions as an implicit promise)
        assert!(matches!(
            acc.on_accept(ballot(6, 1), rec.clone()),
            AcceptReply::Accepted
        ));
        assert_eq!(acc.read_hint().unwrap().0, ballot(6, 1));
        // and afterwards, prepares below that implicit promise are refused
        assert!(matches!(
            acc.on_prepare(ballot(6, 1)),
            PrepareReply::Nack { .. }
        ));
    }

    #[test]
    fn promise_returns_highest_accepted() {
        let mut acc = Acceptor::default();
        let rec = LockRecord::initial(vec![7]);
        acc.on_prepare(ballot(1, 1));
        acc.on_accept(ballot(1, 1), rec.clone());
        match acc.on_prepare(ballot(2, 2)) {
            PrepareReply::Promise { accepted } => {
                let (b, r) = accepted.unwrap();
                assert_eq!(b, ballot(1, 1));
                assert_eq!(r, rec);
            }
            other => panic!("expected promise, got {other:?}"),
        }
    }
}
