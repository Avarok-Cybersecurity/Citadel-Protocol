//! Driving a group-creation subscription to its terminal event.
//!
//! Split out of `remote_ext.rs` so the refusal paths are testable without a
//! running node: the loop lived inside `create_group_with_options`, whose only
//! reachable failure is a server that already holds 256 groups for the owner —
//! 257 protocol round trips to stage, which is not a test anyone should have to
//! run.
//!
//! The loop matched `GroupChannelCreated` and nothing else. It did not call
//! `into_result()` — alone among its neighbours — so `SignalError`,
//! `OutboundRequestRejected` and `InternalServerError` were discarded, and it
//! discarded the server's own answer to a Create it could not perform:
//! `CreateResponse { key: None }`, delivered on this very ticket. The
//! subscription's stream ends only when its receiver drops, and the receiver is
//! what the waiting caller holds, so every one of those meant a caller parked
//! for the life of the process.

use crate::prelude::*;
use futures::{Stream, StreamExt};

/// How a group creation ended.
pub(crate) enum GroupCreation {
    /// The channel opened.
    Created(GroupChannel),
    /// `CreateResponse { key: None }` — the server would not create it.
    /// `create_new_message_group` returns `None` when the owner already holds
    /// 256 groups, or when their `message_groups` entry is missing.
    Refused,
    /// The kernel dropped the subscription without a terminal event.
    Ended,
}

/// Drive `events` to the creation's terminal event.
///
/// Errors carried by the stream are returned rather than skipped, which is what
/// `into_result()` buys and what this loop was missing.
pub(crate) async fn await_group_creation<R: Ratchet, S>(
    events: &mut S,
) -> Result<GroupCreation, NetworkError>
where
    S: Stream<Item = NodeResult<R>> + Unpin,
{
    while let Some(evt) = events.next().await {
        match evt.into_result()? {
            NodeResult::GroupChannelCreated(GroupChannelCreated { channel, .. }) => {
                return Ok(GroupCreation::Created(channel))
            }
            NodeResult::GroupEvent(GroupEvent {
                event: GroupBroadcast::CreateResponse { key: None },
                ..
            }) => return Ok(GroupCreation::Refused),
            _ => {}
        }
    }
    Ok(GroupCreation::Ended)
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio;

    type R = StackedRatchet;

    fn key() -> MessageGroupKey {
        MessageGroupKey::new(1, 1)
    }

    fn group_event(event: GroupBroadcast) -> NodeResult<R> {
        NodeResult::GroupEvent(GroupEvent {
            session_cid: 1,
            ticket: Ticket(1),
            event,
        })
    }

    /// A non-terminal event the wait must step over rather than take as an
    /// answer: the outbound request form, not a response to it.
    fn non_terminal() -> NodeResult<R> {
        group_event(GroupBroadcast::Create {
            initial_invitees: vec![],
            options: Default::default(),
        })
    }

    /// The event the loop used to drop on the floor.
    #[citadel_io::tokio::test]
    async fn a_refusal_is_terminal() {
        let mut events = futures::stream::iter(vec![
            non_terminal(),
            group_event(GroupBroadcast::CreateResponse { key: None }),
        ]);
        assert!(matches!(
            await_group_creation::<R, _>(&mut events).await.unwrap(),
            GroupCreation::Refused
        ));
    }

    /// A SUCCESSFUL create also answers with `CreateResponse`, carrying a key.
    /// Treating that as the refusal would break every group creation, so the
    /// match is on `key: None` and this is the test that says so.
    #[citadel_io::tokio::test]
    async fn a_successful_create_response_is_not_a_refusal() {
        let mut events = futures::stream::iter(vec![group_event(GroupBroadcast::CreateResponse {
            key: Some(key()),
        })]);
        assert!(matches!(
            await_group_creation::<R, _>(&mut events).await.unwrap(),
            GroupCreation::Ended
        ));
    }

    /// `into_result()` is the part the loop was missing. An error on the stream
    /// must come back as an error, not be stepped over on the way to a terminal
    /// event that will never arrive.
    #[citadel_io::tokio::test]
    async fn an_error_on_the_stream_is_returned() {
        let mut events =
            futures::stream::iter(vec![NodeResult::InternalServerError(InternalServerError {
                ticket_opt: Some(Ticket(1)),
                cid_opt: Some(1),
                message: "the node refused the request".to_string(),
            })]);
        let Err(err) = await_group_creation::<R, _>(&mut events).await else {
            panic!("an InternalServerError must not be skipped");
        };
        assert!(
            err.into_string().contains("the node refused the request"),
            "the node's reason must survive to the caller",
        );
    }

    /// A subscription the kernel drops without answering is a failure, not a
    /// hang and not a success.
    #[citadel_io::tokio::test]
    async fn an_ended_subscription_is_not_an_answer() {
        let mut events = futures::stream::iter(Vec::<NodeResult<R>>::new());
        assert!(matches!(
            await_group_creation::<R, _>(&mut events).await.unwrap(),
            GroupCreation::Ended
        ));
    }
}
