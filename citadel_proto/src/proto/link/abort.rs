//! Cancelling an in-flight connect (§9.1, S-C1).
//!
//! A connect the application stopped waiting for (its future dropped by a timeout or a sign-out)
//! used to keep running in the node: it went on hashing, dialling and handshaking, and its
//! provisional entry refused the account's next login ("already in the process of connecting")
//! until a reaper removed it, 8 to 20 seconds later. On a managed node the requester's guard
//! sends `NodeRequest::AbortLink` with the connect's own ticket, and only that ticket can abort
//! it (owner Q12): the node stops the connect at whatever stage it reached, and frees what it
//! held before the next request is read.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::oneshot;
use citadel_io::Mutex;

use crate::proto::node_request::{AbortLink, NodeRequest};
use crate::proto::remote::{NodeRemote, Ticket};

/// The connects in flight on a node, by the ticket that requested each. Empty, and never
/// written, on a legacy node.
#[derive(Clone)]
pub(crate) struct InFlightConnects {
    managed: bool,
    tickets: Arc<Mutex<HashMap<Ticket, oneshot::Sender<()>>>>,
}

/// One connect's registration; dropping it (the connect ended) deregisters it.
pub(crate) struct InFlight {
    ticket: Ticket,
    cancelled: oneshot::Receiver<()>,
    tickets: Arc<Mutex<HashMap<Ticket, oneshot::Sender<()>>>>,
}

impl InFlightConnects {
    pub(crate) fn new(managed: bool) -> Self {
        InFlightConnects {
            managed,
            tickets: Default::default(),
        }
    }

    /// `None` on a legacy node: its connects cannot be aborted.
    pub(crate) fn register(&self, ticket: Ticket) -> Option<InFlight> {
        if !self.managed {
            return None;
        }
        let (cancel, cancelled) = oneshot::channel();
        let _ = self.tickets.lock().insert(ticket, cancel);
        Some(InFlight {
            ticket,
            cancelled,
            tickets: self.tickets.clone(),
        })
    }

    /// Signals the connect `ticket` started, if it is still in flight.
    pub(crate) fn abort(&self, ticket: Ticket) -> bool {
        match self.tickets.lock().remove(&ticket) {
            Some(cancel) => cancel.send(()).is_ok(),
            None => false,
        }
    }

    pub(crate) fn is_managed(&self) -> bool {
        self.managed
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let _ = self.tickets.lock().remove(&self.ticket);
    }
}

/// Runs `stage` unless the connect is aborted first; `None` once it was. The abort is checked
/// first, so a stage that finishes in the same poll as the abort does not carry on past it.
pub(crate) async fn until_aborted<F: Future>(
    in_flight: &mut Option<InFlight>,
    stage: F,
) -> Option<F::Output> {
    match in_flight {
        None => Some(stage.await),
        Some(in_flight) => {
            citadel_io::tokio::select! {
                biased;
                _ = &mut in_flight.cancelled => None,
                out = stage => Some(out),
            }
        }
    }
}

/// Held by a connect's caller while it waits: dropped unanswered, it aborts the connect it names.
/// A legacy node ignores the request.
pub struct AbortGuard<R: Ratchet> {
    remote: NodeRemote<R>,
    ticket: Ticket,
    armed: bool,
}

impl<R: Ratchet> AbortGuard<R> {
    pub fn new(remote: NodeRemote<R>, ticket: Ticket) -> Self {
        AbortGuard {
            remote,
            ticket,
            armed: true,
        }
    }

    /// The connect was answered: nothing to abort.
    pub fn disarm(mut self) {
        self.armed = false;
    }
}

impl<R: Ratchet> Drop for AbortGuard<R> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let request = NodeRequest::AbortLink(AbortLink {
            ticket: self.ticket,
        });
        if let Err(err) = self.remote.send_from_sync(request) {
            log::warn!(target: "citadel", "Unable to abort the connect {}: {err}", self.ticket);
        }
    }
}
