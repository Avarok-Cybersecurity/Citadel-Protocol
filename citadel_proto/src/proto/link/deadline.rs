//! A managed session's login deadline, read from the node's clock.
//!
//! A session still unconnected `LOGIN_EXPIRATION_TIME` after it started is ended by the
//! provisional check. A legacy node schedules that check on the queue worker's own timer; a
//! managed node computes the deadline from its `Clock` when the session starts and asks the queue
//! to run the same check once the clock passes it. The check, and how its end is reported, is the
//! same in both modes; only who keeps the time differs, so a test's clock can cross the deadline
//! without waiting 20 seconds for it.

use std::sync::Arc;

use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::broadcast;
use citadel_link::{Clock, Millis};

use crate::constants::LOGIN_EXPIRATION_TIME;
use crate::proto::link::LinkManagerMode;
use crate::proto::packet_processor::includes::Duration;
use crate::proto::session_queue_handler::{
    QueueFunction, QueueWorkerTicket, SessionQueueWorkerHandle,
};

/// When a session that started now must have connected by, on the node's clock.
pub(crate) struct LoginDeadline {
    at: Millis,
    clock: Arc<dyn Clock>,
}

/// `None` on a legacy node, whose queue keeps the time itself.
pub(crate) fn login_deadline(mode: &LinkManagerMode) -> Option<LoginDeadline> {
    let clock = mode.managed()?.clock().clone();
    Some(LoginDeadline {
        at: clock.now().after(LOGIN_EXPIRATION_TIME),
        clock,
    })
}

impl LoginDeadline {
    /// Runs `check` on the session's queue once the clock passes the deadline, unless the session
    /// stops first.
    pub(crate) fn arm<R: Ratchet>(
        self,
        mut stopped: broadcast::Receiver<()>,
        queue: SessionQueueWorkerHandle<R>,
        key: Option<QueueWorkerTicket>,
        check: impl QueueFunction<R>,
    ) {
        let passed = self.clock.sleep_until(self.at);
        spawn!(async move {
            citadel_io::tokio::select! {
                _ = passed => queue.insert_reserved(key, Duration::ZERO, check),
                _ = stopped.recv() => {}
            }
        });
    }
}
