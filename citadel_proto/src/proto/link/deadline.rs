//! A session's login deadline, on the clock that decides it.
//!
//! A session still unconnected `LOGIN_EXPIRATION_TIME` after it started is ended by the
//! provisional check. A managed node reads the deadline from its `Clock`, so a test's clock can
//! cross it without waiting 20 seconds; a legacy node reads it from the runtime's. The check, and
//! how its end is reported, is the same in both modes.

use std::sync::Arc;

use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::broadcast;
use citadel_link::{Clock, Millis};

use crate::constants::LOGIN_EXPIRATION_TIME;
use crate::error::NetworkError;
use crate::proto::link::{LinkManagerMode, RuntimeClock};
use crate::proto::packet_processor::includes::Duration;
use crate::proto::session_queue_handler::{
    QueueFunction, QueueWorkerTicket, SessionQueueWorkerHandle,
};

/// When a session that started now must have connected by.
#[derive(Clone)]
pub(crate) struct LoginDeadline {
    at: Millis,
    clock: Arc<dyn Clock>,
}

/// The node's clock on a managed node, the runtime's on a legacy one.
pub(crate) fn login_deadline(mode: &LinkManagerMode) -> LoginDeadline {
    let clock: Arc<dyn Clock> = match mode.managed() {
        Some(managed) => managed.clock().clone(),
        None => Arc::new(RuntimeClock::new()),
    };
    LoginDeadline {
        at: clock.now().after(LOGIN_EXPIRATION_TIME),
        clock,
    }
}

impl LoginDeadline {
    /// Whether the deadline has passed, whether or not the check has run yet. A server ends a
    /// login at its own deadline, which starts at its accept, after the client's started at its
    /// request: a login the server hung up on after the client's deadline was ended by the
    /// deadline, even when the client's own check has not run yet.
    pub(crate) fn passed(&self) -> bool {
        self.clock.now() >= self.at
    }

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

/// What a session ended by its login deadline reports, in both modes. One definition: `execute`
/// raises it, and `NodeResult::into_result` names it again by its code when it reaches the caller
/// as the kernel's message, which carries no code (as `refused` does for S-C8).
pub(crate) fn login_deadline_error() -> NetworkError {
    citadel_io::error!(
        citadel_io::ErrorCode::Timeout,
        format!(
            "the session did not connect within its login deadline ({LOGIN_EXPIRATION_TIME:?})"
        )
    )
}

/// Whether `message` is [`login_deadline_error`] as rendered for the kernel.
pub(crate) fn is_login_deadline(message: &str) -> bool {
    message == login_deadline_error().to_string()
}
