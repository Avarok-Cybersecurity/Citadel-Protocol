//! A messenger's background task ends with its connection, and releases the keys it held.
//!
//! The task waits on channels fed by senders inside the ratchet manager it holds, so those
//! channels never close on their own: the task has to see the manager halt. The bare-manager
//! case is the control: it shows the measurement can see a release at all.

use citadel_crypt::endpoint_crypto_container::{EndpointRatchetConstructor, PeerSessionCrypto};
use citadel_crypt::messaging::{MessengerLayerOrderedMessage, RatchetManagerMessengerLayer};
use citadel_crypt::ratchets::ratchet_manager::{
    RatchetManager, RatchetManagerSink, RatchetManagerStream,
};
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_crypt::toolset::Toolset;
use citadel_io::tokio;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm, SecrecyMode, SecurityLevel};
use futures::channel::mpsc::{unbounded, SendError};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Weak};
use std::time::Duration;

type R = StackedRatchet;
type P = MessengerLayerOrderedMessage<String>;
type Mgr = RatchetManager<
    Box<dyn RatchetManagerSink<P, Error = SendError>>,
    Box<dyn RatchetManagerStream<P>>,
    R,
    P,
>;
const PSKS: &[&[u8]] = &[b"psk"];

/// The rekey process stays up until it has seen 2 s without an inbound packet, checking every
/// 500 ms, so a released toolset is gone about 3 s after shutdown. The bound is several times
/// that, and far below the process lifetime a held toolset lasts.
const RELEASED_WITHIN: Duration = Duration::from_secs(10);

/// Two connected managers, plus a `Weak` to each side's toolset.
fn managers() -> (Mgr, Mgr, Vec<Weak<impl Sized>>) {
    let opts = ConstructorOpts::new_vec_init(
        EncryptionAlgorithm::AES_GCM_256 + KemAlgorithm::MlKem,
        SecurityLevel::Standard,
    );
    let mut a = <R as Ratchet>::Constructor::new_alice(opts.clone(), 10, 0).unwrap();
    let mut b =
        <R as Ratchet>::Constructor::new_bob(20, opts, a.stage0_alice().unwrap(), PSKS).unwrap();
    a.stage1_alice(b.stage0_bob().unwrap(), PSKS).unwrap();
    let ca = PeerSessionCrypto::new(Toolset::new(10, a.finish().unwrap()), true);
    let cb = PeerSessionCrypto::new(Toolset::new(20, b.finish().unwrap()), false);
    let weaks = vec![Arc::downgrade(ca.toolset()), Arc::downgrade(cb.toolset())];
    let (tx_a, rx_b) = unbounded();
    let (tx_b, rx_a) = unbounded();
    let ma: Mgr = RatchetManager::new(Box::new(tx_a), Box::new(rx_a), ca, PSKS);
    let mb: Mgr = RatchetManager::new(Box::new(tx_b), Box::new(rx_b), cb, PSKS);
    (ma, mb, weaks)
}

/// Waits until no toolset can be upgraded, failing at the deadline.
async fn assert_released<T>(weaks: &[Weak<T>]) {
    let released = tokio::time::timeout(RELEASED_WITHIN, async {
        while weaks.iter().any(|weak| weak.upgrade().is_some()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let counts: Vec<usize> = weaks.iter().map(Weak::strong_count).collect();
    assert!(
        released.is_ok(),
        "a toolset is still held {RELEASED_WITHIN:?} after teardown (strong counts {counts:?})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shut_down_manager_releases_its_toolset() {
    let (ma, mb, weaks) = managers();
    let _ = ma.shutdown();
    let _ = mb.shutdown();
    drop((ma, mb));
    assert_released(&weaks).await;
}

async fn messenger_teardown(secrecy_mode: SecrecyMode) {
    let (ma, mb, weaks) = managers();
    let (ka, kb) = (ma.clone(), mb.clone());
    let messenger = |manager: Mgr| {
        RatchetManagerMessengerLayer::new(
            manager,
            secrecy_mode,
            None,
            Arc::new(AtomicBool::new(true)),
        )
    };
    let (la, lb) = (messenger(ma), messenger(mb));
    // The protocol's teardown: the connection shuts its manager down, then every handle goes.
    let _ = ka.shutdown();
    let _ = kb.shutdown();
    drop((ka, kb, la.split(), lb.split()));
    assert_released(&weaks).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_best_effort_messenger_releases_its_toolset() {
    messenger_teardown(SecrecyMode::BestEffort).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_perfect_messenger_releases_its_toolset() {
    messenger_teardown(SecrecyMode::Perfect).await;
}

/// A messenger the application still holds ends once its connection has: the halves then read
/// end of stream, and the background task is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_messenger_ends_with_its_connection() {
    use futures::StreamExt;
    let (ma, mb, _weaks) = managers();
    let (ka, kb) = (ma.clone(), mb.clone());
    let (_tx_a, mut rx_a) = RatchetManagerMessengerLayer::new(
        ma,
        SecrecyMode::BestEffort,
        None,
        Arc::new(AtomicBool::new(true)),
    )
    .split();
    let _b = RatchetManagerMessengerLayer::new(
        mb,
        SecrecyMode::BestEffort,
        None,
        Arc::new(AtomicBool::new(true)),
    );
    let _ = ka.shutdown();
    let _ = kb.shutdown();
    let ended = tokio::time::timeout(RELEASED_WITHIN, rx_a.next()).await;
    assert!(
        matches!(ended, Ok(None)),
        "a held messenger still runs {RELEASED_WITHIN:?} after its connection ended"
    );
}
