use super::accept_during;
use citadel_io::tokio;
use citadel_io::tokio_stream::StreamExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A listener whose every accept is a side effect the client can see, as the first packet is.
fn listener(
    answered: Arc<AtomicUsize>,
    connections: usize,
) -> impl citadel_io::tokio_stream::Stream<Item = usize> + Unpin {
    Box::pin(
        citadel_io::tokio_stream::iter(0..connections).then(move |n| {
            let answered = answered.clone();
            async move {
                answered.fetch_add(1, Ordering::SeqCst);
                n
            }
        }),
    )
}

/// Connections that arrive while the node starts are answered during the startup, not after it,
/// and reach the node afterwards in the order they came.
#[tokio::test]
async fn connections_are_answered_while_the_server_starts() {
    let answered = Arc::new(AtomicUsize::new(0));
    let startup = {
        let answered = answered.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            answered.load(Ordering::SeqCst)
        }
    };
    let (answered_during_startup, accepted) = accept_during(listener(answered, 3), startup).await;
    assert_eq!(answered_during_startup, 3);
    assert_eq!(accepted.collect::<Vec<_>>().await, vec![0, 1, 2]);
}

/// A listener that ends during the startup is not polled again, and ends the node's stream after
/// what it accepted.
#[tokio::test]
async fn a_listener_that_ends_during_startup_ends_after_its_connections() {
    let answered = Arc::new(AtomicUsize::new(0));
    let startup = tokio::time::sleep(Duration::from_millis(50));
    let ((), mut accepted) = accept_during(listener(answered, 1), startup).await;
    assert_eq!(accepted.next().await, Some(0));
    assert_eq!(accepted.next().await, None);
    assert_eq!(accepted.next().await, None);
}
