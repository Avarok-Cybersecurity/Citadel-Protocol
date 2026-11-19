//! Waiting, with a deadline, for the event that answers a request.
//!
//! A request's subscription carries only events for that request, but it can stay open and
//! never carry the answer: a peer or server that never replies. Every wait is therefore bounded;
//! an unanswered request is reported, which a caller can act on, instead of parking it for ever.

use citadel_proto::prelude::{NetworkError, NodeResult, Ratchet};
use futures::{Stream, StreamExt};
use std::time::Duration;

/// How long a disconnect or deregistration waits for the server's confirmation. The server
/// answers these itself, so a live one answers at once.
pub(crate) const SERVER_ANSWER_TIMEOUT: Duration = Duration::from_secs(30);

/// Waits up to `within` for the event `answer` recognises, skipping events it does not. An error
/// event on the subscription is the request's failure and is returned as such. `unanswered`
/// makes the error for a deadline passed or a subscription ended with no answer.
pub(crate) async fn await_answer<R, S, T>(
    subscription: &mut S,
    within: Duration,
    what: &str,
    unanswered: impl Fn() -> NetworkError,
    mut answer: impl FnMut(NodeResult<R>) -> Option<Result<T, NetworkError>>,
) -> Result<T, NetworkError>
where
    R: Ratchet,
    S: Stream<Item = NodeResult<R>> + Unpin,
{
    let deadline = citadel_io::time::Instant::now() + within;
    // What the subscription did carry, for the occasion when it does not carry the answer: a
    // non-zero count says it was alive and the answer was never emitted or went elsewhere; zero
    // says it heard nothing at all, which points at the session rather than the routing.
    let mut carried = 0usize;
    loop {
        let remaining = deadline.saturating_duration_since(citadel_io::time::Instant::now());
        match citadel_io::time::timeout(remaining, subscription.next()).await {
            Ok(Some(event)) => {
                carried += 1;
                if let Some(outcome) = answer(event.into_result()?) {
                    return outcome;
                }
            }
            Ok(None) => {
                log::warn!(target: "citadel", "[answer-wait] the subscription for {what} closed unanswered; it carried {carried} other event(s)");
                return Err(unanswered());
            }
            Err(_elapsed) => {
                log::warn!(target: "citadel", "[answer-wait] no answer for {what} within {within:?}; the subscription carried {carried} other event(s)");
                return Err(unanswered());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio;
    use citadel_io::ErrorCode;
    use citadel_proto::prelude::{Disconnect, StackedRatchet, Ticket};

    /// Short, so the deadline is reached quickly; the outer bound only stops a hang.
    const WITHIN: Duration = Duration::from_millis(100);

    fn event(success: bool) -> NodeResult<StackedRatchet> {
        NodeResult::Disconnect(Disconnect {
            ticket: Ticket(1),
            cid_opt: Some(1),
            success,
            conn_type: None,
            message: String::new(),
            disconnect_token: None,
            reason: None,
        })
    }

    fn the_successful_one(event: NodeResult<StackedRatchet>) -> Option<Result<(), NetworkError>> {
        matches!(
            event,
            NodeResult::Disconnect(Disconnect { success: true, .. })
        )
        .then_some(Ok(()))
    }

    #[tokio::test]
    async fn a_request_nobody_answers_fails_at_its_deadline() {
        let mut silent = futures::stream::pending::<NodeResult<StackedRatchet>>();
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            await_answer(
                &mut silent,
                WITHIN,
                "test",
                || citadel_io::error!(ErrorCode::RemoteDisconnectEventMissing),
                the_successful_one,
            ),
        )
        .await
        .expect("the wait outlived its deadline");
        assert_eq!(
            outcome.unwrap_err().code(),
            ErrorCode::RemoteDisconnectEventMissing
        );
    }

    #[tokio::test]
    async fn events_that_do_not_answer_are_skipped() {
        let mut events = futures::stream::iter([event(false), event(false), event(true)]);
        let outcome = await_answer(
            &mut events,
            WITHIN,
            "test",
            || citadel_io::error!(ErrorCode::RemoteDisconnectEventMissing),
            the_successful_one,
        )
        .await;
        assert!(outcome.is_ok(), "{outcome:?}");
    }

    #[tokio::test]
    async fn a_subscription_that_ends_unanswered_is_reported() {
        let mut events = futures::stream::iter([event(false)]);
        let outcome = await_answer(
            &mut events,
            WITHIN,
            "test",
            || citadel_io::error!(ErrorCode::RemoteDeregisterEndedUnexpectedly),
            the_successful_one,
        )
        .await;
        assert_eq!(
            outcome.unwrap_err().code(),
            ErrorCode::RemoteDeregisterEndedUnexpectedly
        );
    }
}
