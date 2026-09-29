//! A failed hole punch is reported on the runtime thread that is driving it,
//! and on the retry path. Rendering an anyhow backtrace there (anyhow's Debug
//! does) symbolizes it synchronously: seconds in a debug build, during which
//! the peer's side of the punch and every other wall-clock bound on that
//! runtime keep running. The failure reports must use Display.
//!
//! Its own test binary, so this is the only test in the process: the backtrace
//! setting is read once per process, on the first capture.

use citadel_io::tokio;
use citadel_wire::udp_traversal::udp_hole_puncher::UdpHolePuncher;
use netbeam::reliable_conn::ReliableOrderedStreamToTarget;
use netbeam::sync::subscription::Subscribable;
use netbeam::sync::test_utils::create_streams_with_addrs;
use std::sync::Mutex;
use std::time::Duration;

struct Recorder(Mutex<Vec<String>>);

impl log::Log for Recorder {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        self.0.lock().unwrap().push(record.args().to_string());
    }

    fn flush(&self) {}
}

static RECORDER: Recorder = Recorder(Mutex::new(Vec::new()));

#[tokio::test]
async fn a_failed_punch_is_reported_without_a_backtrace() {
    std::env::set_var("RUST_LIB_BACKTRACE", "1");
    log::set_logger(&RECORDER).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    // Precondition: errors in this process carry a backtrace, so a Debug
    // rendering would show one and the assertions below can discriminate.
    let probe = format!("{:?}", anyhow::Error::msg("probe"));
    assert!(
        probe.contains("Stack backtrace"),
        "backtraces are not being captured, so this test cannot tell Display from Debug: {probe}"
    );

    let (local, remote) = create_streams_with_addrs().await;

    // The peer joins each attempt's subscription and answers the NAT-type
    // exchange with bytes that do not deserialize, so every attempt fails
    // with an error (not a timeout) and goes down the reporting path.
    let peer = async {
        let mut held = Vec::new();
        loop {
            let stream = remote.initiate_subscription().await.unwrap();
            let _local_nat_type = stream.recv().await.unwrap();
            stream.send_to_peer(b"not a NatType").await.unwrap();
            held.push(stream);
        }
    };

    let punch = UdpHolePuncher::new_timeout(&local, Default::default(), Duration::from_secs(20));
    let result = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(60), punch) => {
            result.expect("the punch neither succeeded nor failed")
        }
        _ = peer => unreachable!("the scripted peer never finishes"),
    };
    assert!(
        result.is_err(),
        "a punch against a garbage-speaking peer succeeded"
    );

    let lines = RECORDER.0.lock().unwrap().clone();
    let failures: Vec<&String> = lines
        .iter()
        .filter(|line| line.contains("[driver] Attempt") && line.contains("failed with error"))
        .collect();
    assert!(
        !failures.is_empty(),
        "no attempt failure was reported, so the reporting path was not exercised: {lines:#?}"
    );

    for line in &lines {
        assert!(
            !line.contains("Stack backtrace"),
            "a hole-punch report rendered its backtrace: {line}"
        );
    }
}
