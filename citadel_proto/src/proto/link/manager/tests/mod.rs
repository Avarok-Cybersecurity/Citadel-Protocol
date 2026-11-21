//! The shell, driven deterministically: every port answers at once, the clock moves only when a
//! test moves it, and each step runs every ready port result before the next input (§11).

mod fixtures;
mod heal;
mod ports;

use std::sync::Arc;

use citadel_io::tokio::sync::mpsc;
use citadel_link::{
    Clock, Incarnation, LinkCore, LinkEvent, LinkInput, LinkSettings, LinkState, Millis, PathStage,
    StableHandle,
};
use citadel_types::crypto::{HeaderObfuscatorSettings, SecrecyMode, SecurityLevel};
use citadel_types::proto::{SessionSecuritySettings, UdpMode};
use futures::{FutureExt, StreamExt};

use super::{RobustConnectionManager, ShellInput};
use fixtures::*;
use ports::*;

type Shell = RobustConnectionManager<ScriptedEstablisher, ScriptedPorts>;

struct Harness {
    m: Shell,
    clock: Arc<ManualClock>,
    script: Arc<Script>,
    ports: Arc<ScriptedPorts>,
    handle: Arc<StableHandle<CountingChannel>>,
    _inbox: mpsc::UnboundedSender<ShellInput<ScriptedEstablisher>>,
}

pub(super) fn settings() -> LinkSettings {
    // The SDK's default suite (rationale for a test default: only the link's steps vary here).
    let security = SessionSecuritySettings {
        security_level: SecurityLevel::Standard,
        secrecy_mode: SecrecyMode::BestEffort,
        crypto_params: crate::proto::misc::session_security_settings::DEFAULT_SESSION_CRYPTO_PARAMS,
        header_obfuscator_settings: HeaderObfuscatorSettings::Disabled,
    };
    LinkSettings {
        security,
        udp_mode: UdpMode::Enabled,
    }
}

impl Harness {
    /// A pair link from `local_cid` toward `peer_cid`, whose rendezvous meets with `plan`.
    pub(super) fn new(local_cid: u64, peer_cid: u64) -> Self {
        let clock = Arc::new(ManualClock::default());
        let script = Arc::new(Script::default());
        let ports = Arc::new(ScriptedPorts {
            plan: direct_then_relay(),
            met: Default::default(),
            events: Default::default(),
            buffers: Default::default(),
            fallbacks: Default::default(),
        });
        let handle = Arc::new(StableHandle::new(CountingChannel::default()));
        let core = LinkCore::new(config(local_cid, peer_cid, settings())).expect("valid config");
        let (tx, rx) = mpsc::unbounded_channel();
        let m = RobustConnectionManager::new(
            core,
            Arc::new(ScriptedEstablisher(script.clone())),
            ports.clone(),
            clock.clone(),
            (),
            handle.clone(),
            rx,
        );
        Harness {
            m,
            clock,
            script,
            ports,
            handle,
            _inbox: tx,
        }
    }

    /// Runs every port result that is ready, until none is.
    /// Runs every port result that is ready, and every wake that is due at the current time
    /// (as the shell's own sleep would), until neither is.
    pub(super) fn settle(&mut self) {
        loop {
            if let Some(Some(done)) = self.m.pending.next().now_or_never() {
                if let Some(input) = self.m.absorb(done) {
                    self.m.apply(input);
                }
                continue;
            }
            let now = self.clock.now();
            if self.m.core.next_wake().is_some_and(|wake| wake <= now) {
                self.m.apply(LinkInput::Tick);
                continue;
            }
            return;
        }
    }

    pub(super) fn input(&mut self, input: LinkInput) {
        self.m.apply(input);
        self.settle();
    }

    pub(super) fn offer(&mut self, incarnation: Incarnation) {
        let path = ScriptedPath(citadel_link::RouteKind::Direct, citadel_link::RouteId(900));
        let link = citadel_link::Link::opened(path, incarnation, self.clock.now());
        self.m.receive(ShellInput::Offer(link));
        self.settle();
    }

    /// Moves the clock to `at` and delivers the tick the core asked for, if it is due.
    pub(super) fn tick_to(&mut self, at: Millis) {
        self.clock.advance_to(at);
        self.settle();
    }

    pub(super) fn start(&mut self) {
        self.input(LinkInput::Start);
    }

    pub(super) fn paths(&self) -> Vec<citadel_link::PathAttemptOutcome> {
        let events = self.ports.events.lock();
        events
            .iter()
            .filter_map(|e| match e {
                LinkEvent::Path(o) => Some(o.clone()),
                _ => None,
            })
            .collect()
    }

    pub(super) fn degraded(&self) -> usize {
        let events = self.ports.events.lock();
        events
            .iter()
            .filter(|e| matches!(e, LinkEvent::Degraded(_)))
            .count()
    }

    pub(super) fn opened(&self) -> Vec<PathStage> {
        self.script
            .opened
            .lock()
            .iter()
            .map(|(stage, _)| *stage)
            .collect()
    }

    pub(super) fn delivered(&self) -> Vec<Incarnation> {
        self.handle.channel().0.lock().clone()
    }

    pub(super) fn up_on(&self) -> Option<citadel_link::RouteKind> {
        match self.m.state() {
            LinkState::Up { route, .. } => Some(route.kind),
            _ => None,
        }
    }
}

#[test]
fn a_pair_opens_direct_and_the_kernel_is_handed_one_channel() {
    let mut h = Harness::new(1, 2);
    h.start();
    assert_eq!(
        h.ports.met.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one rendezvous"
    );
    assert_eq!(h.up_on(), Some(citadel_link::RouteKind::Direct));
    assert_eq!(
        h.opened(),
        vec![PathStage::Direct],
        "the relay is not opened when direct works"
    );
    assert_eq!(
        h.delivered().len(),
        1,
        "one delivery to the kernel's handle"
    );
    let paths = h.paths();
    assert_eq!(paths.len(), 1, "exactly one outcome for the establishment");
    assert_eq!(paths[0].trigger, citadel_link::PathTrigger::Initial);
}

#[test]
fn a_failed_punch_ends_on_the_relay_and_rearms_on_the_clock() {
    let mut h = Harness::new(1, 2);
    h.script.failing.lock().push(PathStage::Direct);
    h.start();
    assert_eq!(h.opened(), vec![PathStage::Direct, PathStage::Relay]);
    assert_eq!(h.up_on(), Some(citadel_link::RouteKind::ServerRelay));
    h.script.failing.lock().clear();
    // The rearm waits its backoff (`rearm.first_wait`, 5 s): nothing before it.
    h.tick_to(Millis(4_999));
    assert_eq!(h.opened().len(), 2, "no punch before the rearm is due");
    h.tick_to(Millis(5_000));
    assert_eq!(h.opened().len(), 3, "the rearm punches once it is due");
    assert_eq!(h.up_on(), Some(citadel_link::RouteKind::Direct));
    assert_eq!(
        h.delivered().len(),
        2,
        "the side route attached to the same handle"
    );
    assert_eq!(h.degraded(), 0, "a relayed link is not degraded");
}
