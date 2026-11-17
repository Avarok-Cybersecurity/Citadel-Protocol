//! Which listener a result reaches, and what a second registration under a live key does.

use super::*;
use crate::proto::node_result::Disconnect;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use futures::StreamExt;

type Handler = KernelAsyncCallbackHandler<StackedRatchet>;

fn disconnect(ticket: u128, cid: Option<u64>) -> NodeResult<StackedRatchet> {
    NodeResult::Disconnect(Disconnect {
        ticket: Ticket(ticket),
        cid_opt: cid,
        success: true,
        conn_type: None,
        message: String::new(),
        disconnect_token: None,
    })
}

fn handler() -> Handler {
    KernelAsyncCallbackHandler {
        inner: Arc::new(Mutex::new(KernelAsyncCallbackHandlerInner {
            map: HashMap::new(),
        })),
    }
}

fn delivered(handler: &Handler, result: NodeResult<StackedRatchet>) -> bool {
    handler.maybe_notify(result).is_none()
}

#[citadel_io::tokio::test]
async fn a_second_listener_for_a_live_key_is_refused_and_the_first_keeps_receiving() {
    let handler = handler();
    let key = CallbackKey::new(Ticket(7), 42);
    let mut first = handler.register_stream(key).unwrap();
    assert!(handler.register_stream(key).is_err());

    assert!(delivered(&handler, disconnect(7, Some(42))));
    assert!(matches!(
        first.next().await,
        Some(NodeResult::Disconnect(_))
    ));
}

#[test]
fn a_result_reaches_the_listener_for_its_ticket_and_cid_first() {
    let handler = handler();
    let mut exact = handler
        .register_stream(CallbackKey::new(Ticket(1), 9))
        .unwrap();
    let mut any_cid = handler
        .register_stream(CallbackKey::ticket_only(Ticket(1)))
        .unwrap();

    assert!(delivered(&handler, disconnect(1, Some(9))));
    assert!(exact.inner.try_recv().is_ok());
    assert!(any_cid.inner.try_recv().is_err());

    // Another CID, or none, falls to the ticket-only listener.
    assert!(delivered(&handler, disconnect(1, Some(10))));
    assert!(delivered(&handler, disconnect(1, None)));
    assert!(any_cid.inner.try_recv().is_ok());
    assert!(any_cid.inner.try_recv().is_ok());
}

#[test]
fn a_listener_registered_with_a_cid_never_receives_a_result_without_one() {
    let handler = handler();
    let _listener = handler
        .register_stream(CallbackKey::new(Ticket(3), 5))
        .unwrap();
    assert!(!delivered(&handler, disconnect(3, None)));
    assert!(!delivered(&handler, disconnect(3, Some(6))));
    assert!(!delivered(&handler, disconnect(4, Some(5))));
}
