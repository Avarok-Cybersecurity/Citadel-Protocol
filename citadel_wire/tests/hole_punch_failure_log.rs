//! A failed hole punch is reported on the runtime thread that is driving it,
//! and on the retry path. Rendering an anyhow backtrace there (anyhow's Debug
//! does) symbolizes it synchronously: seconds in a debug build, during which
//! the peer's side of the punch and every other wall-clock bound on that
//! runtime keep running. The failure reports must use Display.
//!
//! Its own test binary, so this is the only test in the process: the backtrace
//! setting is read once per process, on the first capture.

use bytes::Bytes;
use citadel_io::tokio;
use citadel_wire::udp_traversal::udp_hole_puncher::UdpHolePuncher;
use futures::Future;
use netbeam::reliable_conn::{
    ConnAddr, ReliableOrderedStreamToTarget, ReliableOrderedStreamToTargetExt,
};
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::subscription::Subscribable;
use netbeam::sync::test_utils::create_streams_with_addrs;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The hole-punch control stream's framing, as the puncher speaks it: each
/// side announces the attempt it is on, and each attempt's traffic is tagged
/// with its number.
#[derive(Serialize, Deserialize)]
enum Frame {
    Attempt(usize),
    Data { attempt: usize, payload: Vec<u8> },
}

type IoFuture<'a, T> = Pin<Box<dyn Future<Output = std::io::Result<T>> + Send + 'a>>;

/// The scripted peer's view of one attempt over the control stream. Its reader
/// ends at the local side's next announcement, which it records.
struct PeerLane<S> {
    control: Arc<S>,
    attempt: usize,
    next: Arc<tokio::sync::watch::Sender<Option<usize>>>,
    addrs: (SocketAddr, SocketAddr),
}

impl<S: ReliableOrderedStreamToTarget + 'static> ReliableOrderedStreamToTarget for PeerLane<S> {
    fn send_to_peer<'a, 'b, 'r>(&'a self, input: &'b [u8]) -> IoFuture<'r, ()>
    where
        'a: 'r,
        'b: 'r,
        Self: 'r,
    {
        Box::pin(async move {
            let frame = Frame::Data {
                attempt: self.attempt,
                payload: input.to_vec(),
            };
            self.control.send_serialized(frame).await
        })
    }

    fn recv<'a, 'r>(&'a self) -> IoFuture<'r, Bytes>
    where
        'a: 'r,
        Self: 'r,
    {
        Box::pin(async move {
            loop {
                match self.control.recv_serialized::<Frame>().await? {
                    Frame::Data { attempt, payload } if attempt == self.attempt => {
                        return Ok(Bytes::from(payload))
                    }
                    Frame::Data { .. } => continue,
                    Frame::Attempt(next) => {
                        self.next.send_replace(Some(next));
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "the local side moved on",
                        ));
                    }
                }
            }
        })
    }
}

impl<S> ConnAddr for PeerLane<S> {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.addrs.0)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.addrs.1)
    }
}

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
    // Joins each attempt the local side announces, and answers its NAT type
    // with garbage, so every attempt fails with an error.
    let peer = async {
        let control = Arc::new(remote.initiate_subscription().await.unwrap());
        let addrs = (remote.local_addr().unwrap(), remote.peer_addr().unwrap());
        let next = Arc::new(tokio::sync::watch::channel(None).0);
        let mut attempt = match control.recv_serialized::<Frame>().await.unwrap() {
            Frame::Attempt(attempt) => attempt,
            Frame::Data { .. } => unreachable!("data before the first announcement"),
        };
        let mut held = Vec::new();
        loop {
            control
                .send_serialized(Frame::Attempt(attempt))
                .await
                .unwrap();
            let lane = PeerLane {
                control: control.clone(),
                attempt,
                next: next.clone(),
                addrs,
            };
            let endpoint = NetworkEndpoint::register(remote.node_type(), lane)
                .await
                .unwrap();
            let stream = endpoint.initiate_subscription().await.unwrap();
            let _local_nat_type = stream.recv().await.unwrap();
            stream.send_to_peer(b"not a NatType").await.unwrap();
            // The lane's reader records the local side's next announcement.
            let mut announced = next.subscribe();
            attempt = announced
                .wait_for(|next| next.is_some_and(|next| next > attempt))
                .await
                .unwrap()
                .unwrap();
            held.push((endpoint, stream));
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
