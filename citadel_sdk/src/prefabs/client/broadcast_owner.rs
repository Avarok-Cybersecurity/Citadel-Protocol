//! How a broadcast group's owner runs its closure while accepting registrations.
//!
//! The acceptor answers every inbound registration for as long as the owner is in the group,
//! so it never completes on its own. The owner's handler therefore ends when the owner's
//! closure does, and the acceptor ends with it. Joining the two instead left a release build's
//! handler waiting on the acceptor forever, and a `localhost-testing` build stopped accepting
//! after a test's peer count, which production never does.
use crate::prelude::*;
use citadel_io::tokio::sync::mpsc::UnboundedReceiver;
use futures::Future;
use std::sync::atomic::{AtomicBool, Ordering};

/// The owner's outcome: its closure's, unless the acceptor fails first.
pub(crate) async fn while_accepting(
    owner: impl Future<Output = Result<(), NetworkError>>,
    acceptor: impl Future<Output = Result<(), NetworkError>>,
) -> Result<(), NetworkError> {
    let mut owner = std::pin::pin!(owner);
    citadel_io::tokio::select! {
        res = &mut owner => res,
        res = acceptor => {
            res?;
            owner.await
        }
    }
}

/// Routes the kernel's inbound registrations to the acceptor while it holds this route.
/// Dropping it, as ending the acceptor does, hands them back to the inner kernel before the
/// receiver closes, so a late registration is never sent into a closed channel.
pub(crate) struct RegisterRoute<'a> {
    routing: &'a AtomicBool,
    rx: UnboundedReceiver<PeerSignal>,
}

impl<'a> RegisterRoute<'a> {
    pub(crate) fn open(routing: &'a AtomicBool, rx: UnboundedReceiver<PeerSignal>) -> Self {
        routing.store(true, Ordering::Release);
        Self { routing, rx }
    }

    pub(crate) async fn recv(&mut self) -> Option<PeerSignal> {
        self.rx.recv().await
    }
}

impl Drop for RegisterRoute<'_> {
    fn drop(&mut self) {
        self.routing.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio;
    use std::time::Duration;

    /// A hang guard only: the owner's closure is ready at once, so this never runs out
    /// unless the handler waits on the acceptor.
    const HANG: Duration = Duration::from_secs(5);

    #[citadel_io::tokio::test]
    async fn the_owner_returns_when_its_closure_does_though_the_acceptor_never_ends() {
        let ended = citadel_io::tokio::time::timeout(
            HANG,
            while_accepting(async { Ok(()) }, futures::future::pending()),
        )
        .await;
        assert!(
            matches!(ended, Ok(Ok(()))),
            "the owner's handler waited on the acceptor: {ended:?}"
        );
    }

    #[citadel_io::tokio::test]
    async fn an_acceptor_failure_ends_the_owner_with_it() {
        let failure = citadel_io::error!(
            citadel_io::ErrorCode::BroadcastStreamEndedUnexpectedly,
            "reg_rx"
        );
        let ended = citadel_io::tokio::time::timeout(
            HANG,
            while_accepting(futures::future::pending(), async { Err(failure) }),
        )
        .await
        .expect("the acceptor's failure did not end the owner");
        assert!(ended.is_err());
    }

    #[citadel_io::tokio::test]
    async fn an_owner_that_accepts_nothing_still_runs_its_closure() {
        let ran = AtomicBool::new(false);
        let owner = async {
            citadel_io::tokio::task::yield_now().await;
            ran.store(true, Ordering::Relaxed);
            Ok(())
        };
        while_accepting(owner, async { Ok(()) }).await.unwrap();
        assert!(ran.load(Ordering::Relaxed));
    }

    #[test]
    fn a_dropped_route_hands_registrations_back() {
        let routing = AtomicBool::new(false);
        let (_tx, rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();
        let route = RegisterRoute::open(&routing, rx);
        assert!(routing.load(Ordering::Acquire));
        drop(route);
        assert!(!routing.load(Ordering::Acquire));
    }
}
