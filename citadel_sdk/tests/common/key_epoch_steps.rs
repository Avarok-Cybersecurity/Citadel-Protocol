//! Steps the key-epoch tests share: numbered traffic, the floor check, the disconnect scan.

use crate::dials::settings;
use crate::dials::DEADLINE;
use crate::group::Events;
use crate::shell::{is_accept, FrameHook, Shell};
use citadel_io::tokio;
use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::{NegotiationState, ViolationKind};
use citadel_sdk::prelude::*;
use citadel_sdk::test_common::wait_for_peers;

/// Sends `count` numbered messages from `from`, with `tag` naming the sender.
pub async fn send_numbered(shell: &Shell, tag: &str, from: usize, count: usize) {
    for i in from..from + count {
        shell.send_app(format!("{tag}:{i}").as_bytes()).await;
    }
}

/// The next `count` application messages, which must be the peer's, numbered in order.
pub async fn receive_numbered(shell: &mut Shell, peer: &str, count: usize) {
    for expected in 0..count {
        let body = tokio::time::timeout(DEADLINE, shell.app.recv())
            .await
            .expect("the peer's next message arrives")
            .expect("the channel is open");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            format!("{peer}:{expected}")
        );
    }
}

pub fn applied(state: &NegotiationState<KeyProfile>) -> Option<KeyProfile> {
    match state {
        NegotiationState::Applied { agreed, .. } => Some(*agreed),
        _ => None,
    }
}

/// C5 end to end; C4's version floor is the same check (unit-tested in `floor.rs`) and is
/// asserted here to sit at the epoch's version.
pub async fn floor_refuses_below_the_agreed_level(
    shell: &mut Shell,
    is_a: bool,
    peer_tag: &str,
    next: usize,
) {
    let mut violations = shell.handle.take_violations().expect("first take");
    if is_a {
        tokio::time::timeout(DEADLINE, shell.floors.wait_for(|f| f.is_some()))
            .await
            .expect("b's Retire raises a's floor")
            .expect("the shell is running");
        let floor = shell.handle.floor().expect("a floor");
        assert_eq!(floor.level.value(), SecurityLevel::Extreme.value());
        assert!(
            shell.handle.epoch_of(floor.version).is_some(),
            "the floor is the epoch's version"
        );
    }
    wait_for_peers().await;
    if !is_a {
        shell.set_level(SecurityLevel::Standard).await;
        shell.send_app(b"b:below").await;
        shell.set_level(SecurityLevel::Extreme).await;
        shell.send_app(format!("b:{next}").as_bytes()).await;
    } else {
        let body = tokio::time::timeout(DEADLINE, shell.app.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            String::from_utf8(body).unwrap(),
            format!("{peer_tag}:{next}"),
            "the frame below the floor never reached the application"
        );
        let violation = violations
            .try_recv()
            .expect("the refused frame was reported");
        assert_eq!(violation.kind, ViolationKind::LevelBelowAgreed);
    }
    wait_for_peers().await;
}

pub fn events_hold_a_disconnect(events: &mut Events) -> bool {
    std::iter::from_fn(|| events.try_recv().ok()).any(|event| {
        matches!(
            event,
            NodeResult::Disconnect(_)
                | NodeResult::PeerEvent(PeerEvent {
                    event: PeerSignal::Disconnect { .. },
                    ..
                })
        )
    })
}

/// The link changed in band: the ratchet carries the level, only the Leader triggered the round
/// (D2), nothing was dropped or left unopened, and the connection is the one it was.
pub fn assert_stayed_in_band(
    shell: &Shell,
    me: &str,
    leads: bool,
    target_level: SecurityLevel,
    connection: Option<Ticket>,
    events: &mut Events,
    seen: &[NegotiationState<KeyProfile>],
) {
    assert_eq!(
        shell.refusals.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "{me}'s peer refused no key round"
    );
    let negotiated = shell.handle.negotiated().expect("a profile");
    assert_eq!(
        negotiated.level().value(),
        target_level.value(),
        "{me}'s ratchet carries the agreed level"
    );
    let expected_applies = usize::from(leads);
    assert_eq!(
        shell.applies.load(std::sync::atomic::Ordering::SeqCst),
        expected_applies,
        "only the Leader triggers the round (D2)"
    );
    assert_eq!(
        shell.drops.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "{me}'s link was never dropped: {seen:?}"
    );
    assert_eq!(shell.unopened.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        shell.handle.connection_id().0,
        connection.expect("a P2P connection id").0
    );
    assert!(!events_hold_a_disconnect(events), "{me} saw a Disconnect");
}

/// On the Leader's Accept, before the negotiator sees it, starts a plain rekey of the link: it
/// crosses the steered round the Leader triggers as it accepts. Resolves with its version.
pub fn crossing_hook(
    target: SymmetricIdentifierHandle<StackedRatchet>,
) -> (FrameHook, tokio::sync::oneshot::Receiver<Option<u32>>) {
    let (done_tx, done) = tokio::sync::oneshot::channel();
    let done_tx = std::sync::Mutex::new(Some(done_tx));
    let hook = Box::new(move |envelope: &citadel_negotiation::Envelope| {
        if !is_accept(envelope) {
            return;
        }
        let Some(done_tx) = done_tx.lock().unwrap().take() else {
            return;
        };
        let target = target.clone();
        drop(tokio::spawn(async move {
            let version = target.rekey().await.expect("the plain rekey completes");
            let _ = done_tx.send(version);
        }));
    });
    (hook, done)
}

#[derive(Clone, Copy)]
pub enum Scenario {
    /// Both ends ask for `a`/`b` at once (their proposals cross) while each sends messages.
    Glare { a: SecurityLevel, b: SecurityLevel },
    /// Only `a` asks for Extreme, while both send messages before, during and after.
    Cutover,
    /// After an epoch at Extreme, `b` sends one message at Standard, then one at Extreme.
    Floor,
    /// The higher CID asks for Extreme and, on the Leader's Accept, starts a plain rekey.
    Crossing,
}

pub fn profile(level: SecurityLevel) -> KeyProfile {
    KeyProfile::of(&settings(level))
}
