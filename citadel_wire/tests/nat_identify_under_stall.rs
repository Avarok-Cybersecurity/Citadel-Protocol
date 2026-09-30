//! NAT identification under an executor stall.
//!
//! The SDK's tests (and its consumers' tests) run every node on one `current_thread`
//! runtime, so any synchronous stall freezes identification along with everything else.
//! A stall must make identification *late* or *fail*; it must never turn into a
//! fabricated classification that is then exchanged with the peer at hole-punch step 3
//! as though it were an observation.
//!
//! Both tests use local STUN responders on OS threads (they answer immediately, even
//! while the runtime is frozen), so the only thing that differs from a healthy run is
//! the stall itself. The stall starts only once all three STUN requests have reached
//! the responders. When the stall outlasts the identify deadline, the responders hold
//! their answers until it ends (so they arrive after the deadline, as they would from a
//! responder frozen on the same runtime), which makes the outcome independent of how the
//! scheduler orders the post-stall wakeups.
//!
//! Run: `cargo test -p citadel_wire --test nat_identify_under_stall`
//! (without the `localhost-testing` feature, which short-circuits STUN entirely).

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use citadel_io::tokio;
use citadel_wire::nat_identification::{IpTranslation, NatType, IDENTIFY_TIMEOUT};
use stun::message::{Message, BINDING_SUCCESS};
use stun::xoraddr::XorMappedAddress;

/// A public-looking external IP the responders report, so that a genuine identification
/// (`IpTranslation::Constant`) is distinguishable from `NatType::offline()` (`Identity`).
const MAPPED_IP: &str = "203.0.113.9";

/// Starts a STUN responder on its own OS thread. It answers every BINDING request with a
/// mapping of `MAPPED_IP:<source port>` once `released` is set, and counts the requests it
/// has seen.
fn spawn_stun_responder(seen: Arc<AtomicUsize>, released: Arc<AtomicBool>) -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let mapped_ip = IpAddr::from_str(MAPPED_IP).unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((len, from)) = socket.recv_from(&mut buf) {
            let mut request = Message::new();
            request.raw = buf[..len].to_vec();
            if request.decode().is_err() {
                continue;
            }
            let mut response = Message::new();
            response.transaction_id = request.transaction_id;
            response
                .build(&[
                    Box::new(BINDING_SUCCESS),
                    Box::new(XorMappedAddress {
                        ip: mapped_ip,
                        port: from.port(),
                    }),
                ])
                .unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            while !released.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            let _ = socket.send_to(&response.raw, from);
        }
    });
    addr
}

/// Runs `NatType::identify` against three local responders, freezing the runtime thread for
/// `stall` once all three requests have reached the responders. With `answer_after_stall`
/// the responders answer only once the stall ends; otherwise they answer immediately.
async fn identify_with_stall(
    stall: Duration,
    answer_after_stall: bool,
) -> Result<NatType, citadel_wire::error::FirewallError> {
    let seen = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(!answer_after_stall));
    let servers = (0..3)
        .map(|_| spawn_stun_responder(seen.clone(), released.clone()).to_string())
        .collect::<Vec<_>>();

    let stall_injector = async {
        while seen.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
        // The stall: a synchronous block of the current_thread executor, standing in for
        // backtrace symbolization, inline CPU work, a slow log sink or a laptop pause.
        std::thread::sleep(stall);
        released.store(true, Ordering::SeqCst);
    };

    let (identified, ()) = tokio::join!(NatType::identify(Some(servers)), stall_injector);
    identified
}

/// A stall longer than `IDENTIFY_TIMEOUT` must yield an error (or the true classification),
/// never `NatType::offline()` -- "no NAT, reachable at 127.0.0.1" -- presented as a fact.
#[tokio::test]
async fn a_stall_past_the_identify_deadline_is_not_reported_as_offline() {
    let stall = IDENTIFY_TIMEOUT + Duration::from_millis(500);
    match identify_with_stall(stall, true).await {
        Err(_) => {}
        // An Ok is acceptable only if it is the true classification.
        Ok(nat) => assert!(
            matches!(nat.ip_translation, IpTranslation::Constant { external } if external == IpAddr::from_str(MAPPED_IP).unwrap()),
            "the STUN servers all answered with {MAPPED_IP}, but a {stall:?} stall made identify \
             report a fabricated classification: {nat:?}"
        ),
    }
}

/// The internal IP is a purely local fact (a UDP `connect`, no packet leaves the host). A stall
/// that expires the 2 s ip-info window must not replace it with 127.0.0.1, which is what the
/// peer is then told to punch towards for every wildcard-bound socket.
#[tokio::test]
async fn a_stall_past_the_ip_info_window_does_not_replace_the_internal_ip_with_loopback() {
    let expected = async_ip::get_internal_ipv4()
        .await
        .expect("this test needs a host with a default IPv4 route");
    assert!(!expected.is_loopback());

    // Longer than the 2 s ip-info window, shorter than IDENTIFY_TIMEOUT, so identification
    // itself still completes with the STUN answers that arrived during the stall.
    let stall = Duration::from_millis(2500);
    assert!(stall < IDENTIFY_TIMEOUT);

    let nat = identify_with_stall(stall, false)
        .await
        .expect("STUN answered before IDENTIFY_TIMEOUT, so identification must succeed");
    assert!(
        matches!(nat.ip_translation, IpTranslation::Constant { .. }),
        "STUN must have completed within IDENTIFY_TIMEOUT: {nat:?}"
    );
    let internal = nat.ip_info.as_ref().map(|info| info.internal_ip);
    assert_eq!(
        internal,
        Some(expected),
        "a {stall:?} stall replaced the host's internal IP with a fabricated one: {nat:?}"
    );
}
