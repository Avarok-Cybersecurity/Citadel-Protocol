//! `RobustConnectionManager` (§2.3): the shell around one link's `LinkCore`. It turns every
//! command into a port call and every port result into the core's next input; it never decides
//! anything itself. One manager per link, generic over the establisher, so the C2S and P2P
//! links share it, and the tests drive it with a scripted establisher and a manual clock.

mod dispatch;
pub(crate) mod links;
pub(crate) mod ports;
mod report;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use citadel_io::tokio::sync::mpsc::UnboundedReceiver;
use citadel_link::{
    Clock, Fut, LinkCommand, LinkCore, LinkEstablisher, LinkInput, LinkState, ShutdownReason,
    StableHandle,
};
use futures::stream::FuturesUnordered;
use futures::StreamExt;

use links::{Links, PortDone};
use ports::LinkPorts;

/// What the world tells a link: an input for the core, or the path a peer opened when it
/// healed first and dialled this side (the link value the `PeerOffer` names).
pub(crate) enum ShellInput<E: LinkEstablisher> {
    Core(LinkInput),
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "a responder's accept (C2S, lane L1) offers a path; a P2P pair opens its paths jointly"
        )
    )]
    Offer(citadel_link::Link<E, citadel_link::Pathed>),
    /// The live incarnation's path stopped carrying traffic (the watcher knows the path, not
    /// which incarnation the core runs on it).
    LiveLost(citadel_link::LossCause),
}

/// One link's shell.
pub(crate) struct RobustConnectionManager<E: LinkEstablisher, P: LinkPorts> {
    core: LinkCore,
    est: Arc<E>,
    ports: Arc<P>,
    clock: Arc<dyn Clock>,
    target: E::Target,
    handle: Arc<StableHandle<E::Channel>>,
    links: Links<E>,
    pending: FuturesUnordered<Fut<'static, PortDone<E>>>,
    /// Everything the world tells the link (a lost route, a network change, a peer's offer, the
    /// close). Closing the sender closes the link.
    inbox: UnboundedReceiver<ShellInput<E>>,
    inbox_open: bool,
    /// Inputs a command's port answered at once, applied after the batch that issued it, so
    /// every batch's commands run in the order the core returned them.
    queued: std::collections::VecDeque<LinkInput>,
    applying: bool,
}

/// What woke the loop.
enum Woke<E: LinkEstablisher> {
    Input(ShellInput<E>),
    Done(PortDone<E>),
    Tick,
}

impl<E: LinkEstablisher, P: LinkPorts> RobustConnectionManager<E, P> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        core: LinkCore,
        est: Arc<E>,
        ports: Arc<P>,
        clock: Arc<dyn Clock>,
        target: E::Target,
        handle: Arc<StableHandle<E::Channel>>,
        inbox: UnboundedReceiver<ShellInput<E>>,
    ) -> Self {
        let links = Links::new(core.config().connection);
        RobustConnectionManager {
            core,
            est,
            ports,
            clock,
            target,
            handle,
            links,
            pending: FuturesUnordered::new(),
            inbox,
            inbox_open: true,
            queued: std::collections::VecDeque::new(),
            applying: false,
        }
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the link's events (lane L3)")
    )]
    pub(crate) fn state(&self) -> &LinkState {
        self.core.state()
    }

    /// Starts the link and keeps it existing until it closes.
    pub(crate) async fn run(mut self) -> Self {
        self.apply(LinkInput::Start);
        while !matches!(self.core.state(), LinkState::Closed { .. }) {
            match self.next().await {
                Woke::Input(input) => self.receive(input),
                Woke::Done(done) => {
                    if let Some(input) = self.absorb(done) {
                        self.apply(input);
                    }
                }
                Woke::Tick => self.apply(LinkInput::Tick),
            }
        }
        self
    }

    async fn next(&mut self) -> Woke<E> {
        let wake = self.core.next_wake();
        let clock = self.clock.clone();
        let sleep = async move {
            match wake {
                Some(at) => clock.sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        let idle = self.pending.is_empty();
        let open = self.inbox_open;
        let woke = citadel_io::tokio::select! {
            biased;
            input = self.inbox.recv(), if open => Woke::Input(input.unwrap_or(ShellInput::Core(
                LinkInput::Shutdown { reason: ShutdownReason::Shutdown },
            ))),
            Some(done) = self.pending.next(), if !idle => Woke::Done(done),
            _ = sleep => Woke::Tick,
        };
        // A closed inbox is the world letting go of the link: one shutdown, then the loop drains
        // what is in flight.
        let shutdown = matches!(
            woke,
            Woke::Input(ShellInput::Core(LinkInput::Shutdown { .. }))
        );
        if shutdown && self.inbox.is_closed() {
            self.inbox_open = false;
        }
        woke
    }

    /// An input from the world. An offer's path is kept for the seal the core then asks for.
    pub(crate) fn receive(&mut self, input: ShellInput<E>) {
        match input {
            ShellInput::Core(input) => self.apply(input),
            ShellInput::LiveLost(cause) => {
                if let Some(incarnation) = self.live_incarnation() {
                    self.apply(LinkInput::LinkLost { incarnation, cause });
                }
            }
            ShellInput::Offer(link) => {
                let report = report::path_report(&link);
                let incarnation = link.incarnation();
                self.links.offer(link);
                self.apply(LinkInput::PeerOffer {
                    incarnation,
                    report,
                });
            }
        }
    }

    /// One input through the core, and every command it returns through the ports.
    pub(crate) fn apply(&mut self, input: LinkInput) {
        self.queued.push_back(input);
        if self.applying {
            return;
        }
        self.applying = true;
        while let Some(input) = self.queued.pop_front() {
            let now = self.clock.now();
            for command in self.core.step(now, input) {
                self.dispatch(command);
            }
        }
        self.applying = false;
    }

    fn dispatch(&mut self, command: LinkCommand) {
        dispatch::dispatch(self, command)
    }
}
