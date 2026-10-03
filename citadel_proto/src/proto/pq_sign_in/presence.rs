//! The one stage of a login that may outlast `LOGIN_EXPIRATION_TIME`: waiting for the user to
//! touch a security key. While a key challenge is open, the provisional checker that would end an
//! unconnected session waits until [`KEY_PRESENCE_WINDOW`] after the challenge instead.

use super::security_key::KEY_PRESENCE_WINDOW;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::session::CitadelSession;
use crate::proto::session_queue_handler::QueueWorkerResult;
use crate::proto::state_container::StateContainerInner;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Instant;
use std::time::Duration;

/// The server's window is longer than the client's by this much, so the client, which starts
/// waiting a round trip later, always gives up first.
const SERVER_SLACK: Duration = Duration::from_secs(10);

/// A key challenge was issued (server) or a touch was requested (client).
pub(crate) fn open<R: Ratchet, T: PlatformOps>(session: &CitadelSession<R, T>) {
    let window = if session.is_server {
        KEY_PRESENCE_WINDOW + SERVER_SLACK
    } else {
        KEY_PRESENCE_WINDOW
    };
    inner_mut_state!(session.state_container)
        .connect_state
        .pq
        .presence_until = Some(Instant::now() + window);
}

/// The provisional check: a session still unconnected at its deadline is ended, unless a key
/// touch is pending, in which case the check runs again when the touch window closes.
pub(crate) fn provisional_check<R: Ratchet>(
    state: &mut StateContainerInner<R>,
) -> QueueWorkerResult {
    if state.state.is_connected() {
        return QueueWorkerResult::Complete;
    }
    match state.connect_state.pq.presence_until.take() {
        Some(until) if until > Instant::now() => {
            let remaining = until - Instant::now();
            state
                .queue_handle
                .insert_reserved(None, remaining, |state| provisional_check(&mut **state));
            QueueWorkerResult::Complete
        }
        _ => QueueWorkerResult::EndSession,
    }
}
