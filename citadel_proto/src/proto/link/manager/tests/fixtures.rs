//! A scripted establisher and a manual clock (the ports are in `ports`): the shell under test with no
//! socket, no runtime timer and no randomness. Mocked because the real establisher's steps are
//! a hole punch and a QUIC handshake (the SDK suites run those); here the shell's dispatch is
//! what is tested, and every port answers at once, so a run is a pure function of its inputs.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use citadel_io::Mutex;
use citadel_link::outbox::Undelivered;
use citadel_link::{
    Clock, ConnectionId, Delivered, Fut, Incarnation, KernelChannel, Link, LinkEstablisher,
    LinkSettings, Millis, NatClass, PathFailure, PathHandle, PathStage, PathTrigger, Pathed,
    PunchReuse, RetireReason, RouteId, RouteKind, SealFailure, SealParams, Sealed, SealedSession,
    StageFailure, TimedStage, Unpathed,
};
use citadel_negotiation::ports::BoxFuture;
use citadel_types::crypto::SecBuffer;

use super::ports::nat;

/// Time that moves only when the test moves it.
#[derive(Default)]
pub(super) struct ManualClock(AtomicU64);

impl ManualClock {
    pub(super) fn advance_to(&self, at: Millis) {
        self.0.fetch_max(at.0, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Millis {
        Millis(self.0.load(Ordering::SeqCst))
    }
    fn sleep_until(&self, _at: Millis) -> BoxFuture<'static, ()> {
        // The tests deliver every tick themselves; the shell's own sleep never fires.
        Box::pin(std::future::pending())
    }
}

pub(super) struct ScriptedPath(pub(super) RouteKind, pub(super) RouteId);
impl PathHandle for ScriptedPath {
    fn kind(&self) -> RouteKind {
        self.0
    }
    fn route_id(&self) -> RouteId {
        self.1
    }
    fn migratable(&self) -> bool {
        false
    }
    fn local_nat(&self) -> NatClass {
        nat()
    }
    fn peer_nat(&self) -> Option<NatClass> {
        Some(nat())
    }
}

pub(super) struct ScriptedSeal(pub(super) LinkSettings);
impl SealedSession for ScriptedSeal {
    fn settings(&self) -> LinkSettings {
        self.0
    }
    fn connection_id(&self) -> ConnectionId {
        ConnectionId(7)
    }
    fn latest_version(&self) -> u32 {
        0
    }
}

/// Counts what the kernel was handed: one channel for the link's life (§3.4).
#[derive(Default)]
pub(super) struct CountingChannel(pub(super) Mutex<Vec<Incarnation>>);
impl KernelChannel for CountingChannel {
    fn attach(&self, incarnation: Incarnation) {
        self.0.lock().push(incarnation);
    }
}

/// Whether each stage opens, and a log of every step the shell asked for.
#[derive(Default)]
pub(super) struct Script {
    pub(super) failing: Mutex<Vec<PathStage>>,
    pub(super) opened: Mutex<Vec<(PathStage, PathTrigger)>>,
    pub(super) seals: AtomicU32,
    pub(super) retired: Mutex<Vec<(Incarnation, RetireReason)>>,
}

pub(super) struct ScriptedEstablisher(pub(super) Arc<Script>);

impl LinkEstablisher for ScriptedEstablisher {
    type Target = ();
    type Path = ScriptedPath;
    type Seal = ScriptedSeal;
    type Channel = CountingChannel;
    type Payload = SecBuffer;

    fn open_path<'a>(
        &'a self,
        _: &'a (),
        stage: TimedStage,
        trigger: PathTrigger,
        _: PunchReuse,
        incarnation: Incarnation,
        _: Millis,
    ) -> Fut<'a, Result<Link<Self, Pathed>, PathFailure>> {
        self.0.opened.lock().push((stage.stage, trigger));
        let fails = self.0.failing.lock().contains(&stage.stage);
        let kind = match stage.stage {
            PathStage::Relay => RouteKind::ServerRelay,
            PathStage::Turn => RouteKind::Turn {
                relayed_both: false,
            },
            _ => RouteKind::Direct,
        };
        let route = if kind.is_relay() {
            RouteId::RELAY
        } else {
            RouteId(100 + self.0.opened.lock().len() as u64)
        };
        Box::pin(async move {
            if fails {
                return Err(PathFailure {
                    stage: stage.stage,
                    failure: StageFailure::PunchFailed,
                });
            }
            Ok(Link::opened(
                ScriptedPath(kind, route),
                incarnation,
                Millis(0),
            ))
        })
    }
    fn seal<'a>(
        &'a self,
        link: Link<Self, Pathed>,
        params: &'a SealParams,
        _: Millis,
    ) -> Fut<'a, Result<Link<Self, Sealed>, SealFailure>> {
        self.0.seals.fetch_add(1, Ordering::SeqCst);
        let settings = params.settings;
        Box::pin(async move { Ok(link.seal_with(ScriptedSeal(settings))) })
    }
    fn deliver(
        &self,
        link: Link<Self, Sealed>,
        handle: &citadel_link::StableHandle<CountingChannel>,
    ) -> Link<Self, Delivered> {
        handle.channel().attach(link.incarnation());
        link.delivered()
    }
    fn fork_path(&self, _: &Link<Self, Delivered>) -> Result<Link<Self, Pathed>, PathFailure> {
        Err(PathFailure {
            stage: PathStage::Direct,
            failure: StageFailure::Unsupported,
        })
    }
    fn reattach<'a>(
        &'a self,
        _: Link<Self, Unpathed>,
        _: Link<Self, Pathed>,
        _: Millis,
    ) -> Fut<'a, Result<Link<Self, Sealed>, SealFailure>> {
        Box::pin(async { Err(SealFailure::UnknownSeal) })
    }
    fn retire(
        &self,
        old: Link<Self, Delivered>,
        reason: RetireReason,
    ) -> Fut<'_, Vec<Undelivered<SecBuffer>>> {
        self.0.retired.lock().push((old.incarnation(), reason));
        Box::pin(async { Vec::new() })
    }
}
