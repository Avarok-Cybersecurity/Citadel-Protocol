//! A transport ending is ordinary teardown for every subscription still on it. Their closes used
//! to log one WARN each (`[MetaActionSync/close] "channel closed"`), which buried real warnings in
//! every CI log; and a subscription dropped after the end still spawned a close that could only
//! fail.
//!
//! Its own test binary: it installs the process's logger.

mod common;

use citadel_io::tokio;
use netbeam::sync::subscription::Subscribable;
use netbeam::sync::wire::WireRevision;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

const CLOSE_LOG: &str = "[MetaActionSync/close]";
const HANG_GUARD: Duration = Duration::from_secs(30);

struct Recorder(StdMutex<Vec<(log::Level, String)>>);

impl log::Log for Recorder {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let line = record.args().to_string();
        if line.contains(CLOSE_LOG) {
            self.0.lock().unwrap().push((record.level(), line));
        }
    }

    fn flush(&self) {}
}

static RECORDER: Recorder = Recorder(StdMutex::new(Vec::new()));

fn close_lines() -> Vec<(log::Level, String)> {
    RECORDER.0.lock().unwrap().clone()
}

async fn until(mut done: impl FnMut() -> bool, what: &str) {
    tokio::time::timeout(HANG_GUARD, async {
        while !done() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

#[tokio::test]
async fn subscriptions_ended_by_the_transport_close_quietly() {
    log::set_logger(&RECORDER).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    let (receiver, initiator, link) = common::connected(WireRevision::Exchanged).await;
    let (waiting, _peer_keeps_its_end) = tokio::join!(
        receiver.initiate_subscription(),
        initiator.initiate_subscription()
    );
    let (after_end, _peer_end) = tokio::join!(
        receiver.initiate_subscription(),
        initiator.initiate_subscription()
    );
    let (after_end, _waiting_peer) = (after_end.unwrap(), _peer_keeps_its_end.unwrap());
    let _ = _peer_end.unwrap();

    // This close waits for the peer's half, which never comes: the transport ends first.
    drop(waiting.unwrap());
    link.cut();
    until(
        || receiver.subscriptions().read().is_empty(),
        "the receiver never noticed the transport end",
    )
    .await;

    // Dropped after the end: nothing to wait for, so nothing is spawned.
    let metrics = tokio::runtime::Handle::current().metrics();
    let tasks_before = metrics.num_alive_tasks();
    drop(after_end);
    assert_eq!(
        metrics.num_alive_tasks(),
        tasks_before,
        "a close was spawned for a subscription whose transport had already ended"
    );

    until(
        || !close_lines().is_empty(),
        "the close cut short by the transport end never finished",
    )
    .await;
    let warnings: Vec<_> = close_lines()
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect();
    assert!(
        warnings.is_empty(),
        "teardown was logged as a fault: {warnings:?}"
    );
}
