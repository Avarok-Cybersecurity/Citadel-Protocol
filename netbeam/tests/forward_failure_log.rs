//! A packet the multiplexer cannot forward is routine (it names a channel
//! that has already closed). Logging it must not render the anyhow backtrace:
//! symbolizing one blocks the runtime thread for seconds in a debug build, and
//! every wall-clock bound sharing that thread (the hole punch, most of all)
//! then expires.
//!
//! Its own test binary, so this is the only test in the process: the backtrace
//! setting is read once per process, on the first capture.

use async_trait::async_trait;
use bytes::Bytes;
use citadel_io::tokio;
use citadel_io::tokio::sync::{mpsc, Mutex};
use netbeam::reliable_conn::ReliableOrderedStreamToTarget;
use netbeam::sync::network_application::NetworkApplication;
use netbeam::sync::RelativeNodeType;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

const FORWARD_FAILURE: &str = "Unable to forward packet";

struct Recorder(StdMutex<Vec<String>>);

impl log::Log for Recorder {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        self.0.lock().unwrap().push(record.args().to_string());
    }

    fn flush(&self) {}
}

static RECORDER: Recorder = Recorder(StdMutex::new(Vec::new()));

/// The remote end, played by the test: whatever it queues is what the
/// multiplexer reads.
struct ScriptedPeer {
    inbound: Mutex<mpsc::UnboundedReceiver<Bytes>>,
}

#[async_trait]
impl ReliableOrderedStreamToTarget for ScriptedPeer {
    async fn send_to_peer(&self, _input: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    }
}

fn forward_failures() -> Vec<String> {
    RECORDER
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|line| line.contains(FORWARD_FAILURE))
        .cloned()
        .collect()
}

#[tokio::test]
async fn an_unforwardable_packet_is_logged_without_its_backtrace() {
    std::env::set_var("RUST_LIB_BACKTRACE", "1");
    log::set_logger(&RECORDER).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    // Precondition: errors in this process do carry a backtrace, so a Debug
    // rendering would show one and the assertion below can discriminate.
    let probe = format!("{:?}", anyhow::Error::msg("probe"));
    assert!(
        probe.contains("Stack backtrace"),
        "backtraces are not being captured, so this test cannot tell Display from Debug: {probe}"
    );

    let (tx, rx) = mpsc::unbounded_channel();
    let _app = NetworkApplication::register(
        RelativeNodeType::Receiver,
        ScriptedPeer {
            inbound: Mutex::new(rx),
        },
    )
    .await
    .unwrap();

    tx.send(Bytes::from_static(b"not a multiplexed packet"))
        .unwrap();

    let logged = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let lines = forward_failures();
            if !lines.is_empty() {
                return lines;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the forward failure was never logged");

    for line in logged {
        assert!(
            !line.contains("Stack backtrace"),
            "the forward failure was logged with its backtrace: {line}"
        );
    }
}
