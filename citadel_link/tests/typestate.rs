//! The ordered sequence with a real (in-memory) establisher: the positive control for the
//! compile-fail doc tests in `typestate`, which pin each forbidden step to its error code.

use std::future::ready;

use citadel_link::outbox::{Payload, Undelivered};
use citadel_link::{
    ConnectionId, Delivered, Fut, Incarnation, KernelChannel, Link, LinkEstablisher, LinkSettings,
    Millis, NatClass, PathFailure, PathHandle, PathTrigger, Pathed, PunchReuse, RetireReason,
    RouteId, RouteKind, SealFailure, SealParams, Sealed, SealedSession, StableHandle, TimedStage,
    Unpathed,
};

mod common;

struct Path(u64);
struct Seal(LinkSettings);
struct Channel(std::sync::Mutex<Vec<Incarnation>>);
struct Bytes(Vec<u8>);

impl Payload for Bytes {
    fn byte_len(&self) -> usize {
        self.0.len()
    }
    fn wipe(&mut self) {
        self.0.fill(0);
    }
}

impl PathHandle for Path {
    fn kind(&self) -> RouteKind {
        RouteKind::Direct
    }
    fn route_id(&self) -> RouteId {
        RouteId(self.0)
    }
    fn migratable(&self) -> bool {
        false
    }
    fn local_nat(&self) -> NatClass {
        common::nat()
    }
    fn peer_nat(&self) -> Option<NatClass> {
        None
    }
}

impl SealedSession for Seal {
    fn settings(&self) -> LinkSettings {
        self.0
    }
    fn connection_id(&self) -> ConnectionId {
        ConnectionId(1)
    }
    fn latest_version(&self) -> u32 {
        0
    }
}

impl KernelChannel for Channel {
    fn attach(&self, incarnation: Incarnation) {
        self.0.lock().unwrap().push(incarnation);
    }
}

struct Memory;

impl LinkEstablisher for Memory {
    type Target = u64;
    type Path = Path;
    type Seal = Seal;
    type Channel = Channel;
    type Payload = Bytes;

    fn open_path<'a>(
        &'a self,
        target: &'a u64,
        _: TimedStage,
        _: PathTrigger,
        _: PunchReuse,
        incarnation: Incarnation,
        at: Millis,
    ) -> Fut<'a, Result<Link<Self, Pathed>, PathFailure>> {
        Box::pin(ready(Ok(Link::opened(Path(*target), incarnation, at))))
    }

    fn seal<'a>(
        &'a self,
        link: Link<Self, Pathed>,
        params: &'a SealParams,
        _: Millis,
    ) -> Fut<'a, Result<Link<Self, Sealed>, SealFailure>> {
        Box::pin(ready(Ok(link.seal_with(Seal(params.settings)))))
    }

    fn deliver(
        &self,
        link: Link<Self, Sealed>,
        handle: &StableHandle<Channel>,
    ) -> Link<Self, Delivered> {
        handle.channel().attach(link.incarnation());
        link.delivered()
    }

    fn fork_path(&self, live: &Link<Self, Delivered>) -> Result<Link<Self, Pathed>, PathFailure> {
        let next = live.incarnation().next().expect("room for one more");
        Ok(Link::opened(Path(live.path().0), next, live.opened_at()))
    }

    fn reattach<'a>(
        &'a self,
        held: Link<Self, Unpathed>,
        path: Link<Self, Pathed>,
        _: Millis,
    ) -> Fut<'a, Result<Link<Self, Sealed>, SealFailure>> {
        Box::pin(ready(Ok(path.reattach_seal(held))))
    }

    fn retire(
        &self,
        old: Link<Self, Delivered>,
        _: RetireReason,
    ) -> Fut<'_, Vec<Undelivered<Bytes>>> {
        let _ = old.into_parts();
        Box::pin(ready(Vec::new()))
    }
}

fn now<T>(fut: Fut<'_, T>) -> T {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let mut fut = fut;
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => v,
        std::task::Poll::Pending => panic!("the in-memory establisher never waits"),
    }
}

#[test]
fn path_then_seal_then_deliver_then_reattach_keeps_the_incarnation() {
    let est = Memory;
    let handle = StableHandle::new(Channel(Default::default()));
    let first = Incarnation::first(ConnectionId(1));
    let stage = common::direct_then_relay().stages[0];
    let params = SealParams {
        settings: common::settings(citadel_types::crypto::SecurityLevel::High),
    };
    let pathed = now(est.open_path(
        &7,
        stage,
        PathTrigger::Initial,
        PunchReuse::Fresh,
        first,
        Millis(0),
    ))
    .unwrap();
    let sealed = now(est.seal(pathed, &params, Millis(1))).unwrap();
    let live = est.deliver(sealed, &handle);
    assert_eq!(live.seal().settings(), params.settings);
    let forked = est.fork_path(&live).unwrap();
    assert_eq!(forked.incarnation().n, 2);
    let (held, _dead) = live.lose_path();
    let fresh = now(est.open_path(
        &8,
        stage,
        PathTrigger::Initial,
        PunchReuse::Reattached,
        first,
        Millis(2),
    ))
    .unwrap();
    let back = est.deliver(now(est.reattach(held, fresh, Millis(3))).unwrap(), &handle);
    assert_eq!(
        back.incarnation(),
        first,
        "a reattach keeps the incarnation"
    );
    assert_eq!(back.path().route_id(), RouteId(8), "on the new path");
    assert_eq!(*handle.channel().0.lock().unwrap(), [first, first]);
    assert!(now(est.retire(back, RetireReason::Closing)).is_empty());
}
