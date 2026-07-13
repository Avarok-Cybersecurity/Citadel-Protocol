//! Wire format for group lock traffic. One [`GroupPacket`] envelope per message,
//! bincode-encoded over the caller-supplied per-pair reliable ordered streams.
//! Per-pair FIFO gives no cross-member order, so nothing here relies on arrival
//! order: consensus rounds are correlated by `req_id` and ordered by [`Ballot`].

use crate::sync::group::record::LockRecord;
use crate::sync::group::{LockId, MemberId};
use serde::{Deserialize, Serialize};

/// Proposal number. The `Ord` derive yields the lexicographic (counter, proposer)
/// order — exactly the Lamport (timestamp, member id) total-order tiebreak.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ballot {
    pub counter: u64,
    pub proposer: MemberId,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum GroupMsg {
    // ---- consensus (CAS rounds) ----
    Prepare {
        ballot: Ballot,
    },
    Promise {
        ballot: Ballot,
        accepted: Option<(Ballot, LockRecord)>,
    },
    PrepareNack {
        ballot: Ballot,
        promised: Ballot,
    },
    Accept {
        ballot: Ballot,
        record: LockRecord,
    },
    Accepted {
        ballot: Ballot,
    },
    AcceptNack {
        ballot: Ballot,
        promised: Ballot,
    },
    // ---- hints (never gate safety) ----
    /// Cheap read of a voter's highest accepted state; the proposer assembles a
    /// majority of these for wait-loop polling and janitor observation snapshots.
    ReadHint,
    ReadHintRsp {
        accepted: Option<(Ballot, LockRecord)>,
    },
    /// Best-effort wake sent by a releaser to members whose queue entries may have
    /// become admissible. Loss is tolerated (waiter_poll_interval backstop).
    Nudge,
}

impl GroupMsg {
    /// Whether this message is a request serviced by the voter task (vs a response
    /// routed back to a pending proposer round).
    pub fn is_voter_request(&self) -> bool {
        matches!(
            self,
            Self::Prepare { .. } | Self::Accept { .. } | Self::ReadHint
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GroupPacket {
    pub lock_id: LockId,
    pub from: MemberId,
    /// Correlates responses with the proposer round (or hint gather) that issued the
    /// request. Voter requests echo the id back in the response.
    pub req_id: u64,
    /// Digest of the shared [`crate::sync::group::GroupLockConfig`]; packets with a
    /// mismatched digest are dropped and logged (fail-fast on split configs).
    pub config_digest: u64,
    pub msg: GroupMsg,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ballot_order_is_counter_then_member() {
        let a = Ballot {
            counter: 1,
            proposer: MemberId(9),
        };
        let b = Ballot {
            counter: 2,
            proposer: MemberId(1),
        };
        let c = Ballot {
            counter: 2,
            proposer: MemberId(2),
        };
        assert!(a < b && b < c);
    }

    #[test]
    fn roundtrip_bincode() {
        let pkt = GroupPacket {
            lock_id: LockId(7),
            from: MemberId(3),
            req_id: 42,
            config_digest: 99,
            msg: GroupMsg::Prepare {
                ballot: Ballot {
                    counter: 5,
                    proposer: MemberId(3),
                },
            },
        };
        let bytes = bincode::serialize(&pkt).unwrap();
        let back = bincode::deserialize::<GroupPacket>(&bytes).unwrap();
        assert_eq!(back.lock_id, pkt.lock_id);
        assert!(matches!(back.msg, GroupMsg::Prepare { ballot } if ballot.counter == 5));
    }
}
