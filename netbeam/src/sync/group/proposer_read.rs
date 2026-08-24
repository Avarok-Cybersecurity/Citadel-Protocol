//! Proposer support split from `proposer.rs` (exact piecewise copy): the
//! `ReadHint` majority gather plus the per-phase budget / backoff helpers the
//! round driver shares with it.

use crate::sync::group::engine::Engine;
use crate::sync::group::engine_util::{ms, PendingRound};
use crate::sync::group::proposer::ProposeError;
use crate::sync::group::record::LockRecord;
use crate::sync::group::wire::{Ballot, GroupMsg};
use citadel_io::tokio::time::timeout;
use rand::Rng;
use std::time::Duration;

impl Engine {
    /// Majority read of the highest accepted record (polling/observation hint).
    pub(crate) async fn quorum_read(
        &self,
        deadline_ms: u64,
    ) -> Result<Option<(Ballot, LockRecord)>, ProposeError> {
        loop {
            let req_id = self.next_req_id();
            let mut pending = self.register_pending(req_id);
            let result = self
                .quorum_read_once(req_id, &mut pending, deadline_ms)
                .await;
            drop(pending);
            match result {
                Some(highest) => return Ok(highest),
                None => {
                    if self.now_ms() >= deadline_ms {
                        return Err(ProposeError::QuorumUnavailable);
                    }
                    self.backoff().await;
                }
            }
        }
    }

    async fn quorum_read_once(
        &self,
        req_id: u64,
        pending: &mut PendingRound<'_>,
        deadline_ms: u64,
    ) -> Option<Option<(Ballot, LockRecord)>> {
        let rx = &mut pending.rx;
        let majority = self.cfg.majority();
        self.broadcast(req_id, &GroupMsg::ReadHint);
        let mut highest: Option<(Ballot, LockRecord)> = None;
        let mut replies = 0usize;
        if let Some(GroupMsg::ReadHintRsp { accepted }) = self.local_vote(&GroupMsg::ReadHint) {
            replies += 1;
            merge_accepted(&mut highest, accepted);
        }
        let phase_deadline = self.phase_deadline(deadline_ms);
        while replies < majority {
            match timeout(phase_deadline, rx.recv()).await {
                Ok(Some((_, GroupMsg::ReadHintRsp { accepted }))) => {
                    replies += 1;
                    merge_accepted(&mut highest, accepted);
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return None,
            }
        }
        Some(highest)
    }

    /// Per-phase gather budget: round timeout clipped to the op deadline.
    pub(super) fn phase_deadline(&self, deadline_ms: u64) -> Duration {
        let remaining = deadline_ms.saturating_sub(self.now_ms());
        self.cfg
            .round_timeout()
            .min(Duration::from_millis(remaining.max(1)))
    }

    /// Jittered dueling-proposer backoff: `cas_backoff_base` ±50%.
    pub(super) async fn backoff(&self) {
        let base = ms(self.cfg.cas_backoff_base()).max(1);
        let jittered =
            rand::thread_rng().gen_range((base / 2).max(1)..=base.saturating_add(base / 2));
        citadel_io::time::sleep(Duration::from_millis(jittered)).await;
    }
}

pub(super) fn merge_accepted(
    into: &mut Option<(Ballot, LockRecord)>,
    candidate: Option<(Ballot, LockRecord)>,
) {
    if let Some((b, rec)) = candidate {
        match into {
            Some((cur, _)) if *cur >= b => {}
            _ => *into = Some((b, rec)),
        }
    }
}
