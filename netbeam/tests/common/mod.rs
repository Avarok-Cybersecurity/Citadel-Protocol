//! An in-memory reliable ordered link for the pairing tests. A send is delivered at once, so a
//! future polled once has sent everything it sends before it first waits, and the test can cut
//! the link to end both transports.

#![allow(dead_code)]

use async_trait::async_trait;
use bytes::Bytes;
use citadel_io::tokio;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::{watch, Mutex};
use netbeam::reliable_conn::ReliableOrderedStreamToTarget;
use netbeam::sync::network_application::NetworkApplication;
use netbeam::sync::wire::WireRevision;
use netbeam::sync::RelativeNodeType;

pub struct MemPipe {
    tx: UnboundedSender<Bytes>,
    rx: Mutex<UnboundedReceiver<Bytes>>,
    cut: watch::Receiver<bool>,
}

fn closed() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, "link closed")
}

#[async_trait]
impl ReliableOrderedStreamToTarget for MemPipe {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        if *self.cut.borrow() {
            return Err(closed());
        }
        self.tx
            .send(Bytes::copy_from_slice(input))
            .map_err(|_| closed())
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        let mut cut = self.cut.clone();
        let mut rx = self.rx.lock().await;
        tokio::select! {
            biased;
            _ = cut.wait_for(|cut| *cut) => Err(closed()),
            packet = rx.recv() => packet.ok_or_else(closed),
        }
    }
}

/// Ends both directions of the link.
pub struct Link(watch::Sender<bool>);

impl Link {
    pub fn cut(&self) {
        self.0.send_replace(true);
    }
}

/// A connected (receiver, initiator) pair speaking `wire`.
pub async fn connected(wire: WireRevision) -> (NetworkApplication, NetworkApplication, Link) {
    let (a_tx, a_rx) = unbounded_channel();
    let (b_tx, b_rx) = unbounded_channel();
    let (cut_tx, cut_rx) = watch::channel(false);
    let a = MemPipe {
        tx: a_tx,
        rx: Mutex::new(b_rx),
        cut: cut_rx.clone(),
    };
    let b = MemPipe {
        tx: b_tx,
        rx: Mutex::new(a_rx),
        cut: cut_rx,
    };
    let (receiver, initiator) = tokio::join!(
        NetworkApplication::register(RelativeNodeType::Receiver, a, wire),
        NetworkApplication::register(RelativeNodeType::Initiator, b, wire)
    );
    (receiver.unwrap(), initiator.unwrap(), Link(cut_tx))
}
