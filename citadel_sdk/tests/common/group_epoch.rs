//! Shared scaffolding for group tests where an owner and two members race an epoch change.

use citadel_io::tokio;
use citadel_sdk::prelude::*;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Not yet known.
pub const UNSET: u64 = u64::MAX;
/// Safety bound for a reader waiting on the next message; exceeding it ends the read and the
/// test's outcome assertion reports what was missing. Not a latency assertion.
pub const IDLE_BOUND: Duration = Duration::from_secs(30);

/// Mutually peer-register `me` with `peer`. Both sides call it at the same barrier phase.
pub async fn befriend(
    conn: &CitadelClientServerConnection<StackedRatchet>,
    cid: u64,
    me: &str,
    peer: &str,
) -> Result<(), NetworkError> {
    let status = conn
        .propose_target(cid, peer.to_string())
        .await?
        .register_to_peer()
        .await?;
    assert!(
        status.is_accepted(),
        "{me} → {peer}: peer registration refused"
    );
    Ok(())
}

/// The index of an `a-N` message.
pub fn parse_idx(payload: &[u8]) -> Option<u64> {
    std::str::from_utf8(payload)
        .ok()?
        .strip_prefix("a-")?
        .parse()
        .ok()
}

/// What one node read of A's `a-N` messages.
#[derive(Default)]
pub struct Reader {
    pub seen: Mutex<BTreeSet<u64>>,
    /// Every index read, in the order the channel yielded them
    pub order: Mutex<Vec<u64>>,
    pub dropped: AtomicU64,
}

impl Reader {
    /// Record that `idx` was read, after everything recorded before it.
    pub fn record(&self, idx: u64) {
        let _ = self.seen.lock().unwrap().insert(idx);
        self.order.lock().unwrap().push(idx);
    }

    /// Each index read after a later one, as (earlier read, later read) pairs.
    fn out_of_order(&self) -> Vec<(u64, u64)> {
        let order = self.order.lock().unwrap();
        order
            .windows(2)
            .filter(|pair| pair[1] <= pair[0])
            .map(|pair| (pair[0], pair[1]))
            .collect()
    }

    fn missing(&self, range: std::ops::RangeInclusive<u64>) -> Vec<u64> {
        let seen = self.seen.lock().unwrap();
        range.filter(|idx| !seen.contains(idx)).collect()
    }
}

/// What the owner and the joiner B read of A's `a-N` messages.
pub struct Reads {
    /// The first index A sent after it saw B's channel open
    pub first_after_join: AtomicU64,
    /// A's last index
    pub final_idx: AtomicU64,
    pub owner: Reader,
    pub b: Reader,
}

impl Default for Reads {
    fn default() -> Self {
        Self {
            first_after_join: AtomicU64::new(UNSET),
            final_idx: AtomicU64::new(UNSET),
            owner: Reader::default(),
            b: Reader::default(),
        }
    }
}

impl Reads {
    /// The owner must have read every message A sent, and B every one A sent after B's channel
    /// opened, each in the order A sent them, and neither may have been handed a message it could
    /// not read (`MessageDropped` on its channel); otherwise panic with `lost`, then `context`,
    /// then what each one missed or read out of order.
    pub fn assert_nothing_lost(&self, context: &str, lost: &str) {
        let final_idx = self.final_idx.load(Ordering::SeqCst);
        let first_after_join = self.first_after_join.load(Ordering::SeqCst);
        assert_ne!(final_idx, UNSET, "A never finished sending");
        assert_ne!(
            first_after_join, UNSET,
            "A sent nothing after B's channel opened"
        );
        let owner_missing = self.owner.missing(0..=final_idx);
        let b_missing = self.b.missing(first_after_join..=final_idx);
        let owner_dropped = self.owner.dropped.load(Ordering::SeqCst);
        let b_dropped = self.b.dropped.load(Ordering::SeqCst);
        let owner_reordered = self.owner.out_of_order();
        let b_reordered = self.b.out_of_order();
        let report = format!(
            "{context}A sent a-0..=a-{final_idx}; B's channel opened before a-{first_after_join}. \
             Owner missing {} {owner_missing:?} (MessageDropped seen: {}); \
             B missing {} of those sent after its join {b_missing:?} (MessageDropped seen: {}); \
             out of order (read, then read next) owner {owner_reordered:?}, B {b_reordered:?}",
            owner_missing.len(),
            owner_dropped,
            b_missing.len(),
            b_dropped,
        );
        log::warn!(target: "citadel", "{report}");
        assert!(
            owner_missing.is_empty()
                && b_missing.is_empty()
                && owner_dropped + b_dropped == 0
                && owner_reordered.is_empty()
                && b_reordered.is_empty(),
            "{lost}: {report}"
        );
    }
}

/// Read `a_cid`'s `a-N` messages into `reader` until the one at `final_idx` arrives (or the idle
/// bound passes), counting every `MessageDropped`.
pub async fn read_until_final(
    channel: &mut GroupChannel,
    a_cid: u64,
    final_idx: &AtomicU64,
    reader: &Reader,
    who: &str,
) {
    loop {
        let final_idx = final_idx.load(Ordering::SeqCst);
        if final_idx != UNSET && reader.seen.lock().unwrap().contains(&final_idx) {
            return;
        }
        match tokio::time::timeout(IDLE_BOUND, channel.recv()).await {
            Ok(Some(GroupBroadcastPayload::Message {
                payload, sender, ..
            })) if sender == a_cid => {
                if let Some(idx) = parse_idx(payload.as_ref()) {
                    reader.record(idx);
                }
            }
            Ok(Some(GroupBroadcastPayload::Event {
                payload: GroupBroadcast::MessageDropped { .. },
            })) => {
                let _ = reader.dropped.fetch_add(1, Ordering::SeqCst);
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                log::warn!(target: "citadel", "[{who}] group channel closed");
                return;
            }
            Err(_) => {
                log::warn!(target: "citadel", "[{who}] no message for {IDLE_BOUND:?}; ending the read");
                return;
            }
        }
    }
}

#[cfg(feature = "localhost-testing")]
/// Wait until the server has relayed `count` more messages from `sender`, each to every member.
/// This is observed at the server, so it does not wait on `sender` handling anything inbound
/// (its group traffic is handled in order, and may be behind a Commit it has not applied yet).
pub async fn relayed(
    relays: &mut tokio::sync::mpsc::UnboundedReceiver<
        citadel_proto::test_hooks::GroupMessageRelayed,
    >,
    sender: u64,
    count: u64,
) {
    let mut relayed = 0;
    while relayed < count {
        let relay = relays.recv().await.expect("the relay observer closed");
        if relay.sender == sender {
            assert!(
                relay.complete,
                "the server could not relay a message: {relay:?}"
            );
            relayed += 1;
        }
    }
}

/// Run the server and three client nodes to completion, failing on error or timeout.
pub async fn run_trio<S, O, A, B, SX, OX, AX, BX>(server: S, o: O, a: A, b: B)
where
    S: std::future::Future<Output = Result<SX, NetworkError>>,
    O: std::future::Future<Output = Result<OX, NetworkError>>,
    A: std::future::Future<Output = Result<AX, NetworkError>>,
    B: std::future::Future<Output = Result<BX, NetworkError>>,
{
    let clients = async move { futures::future::try_join3(o, a, b).await.map(|_| ()) };
    let task = async move {
        tokio::select! {
            res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
            res = clients => res,
        }
    };
    let result = citadel_io::time::runnable_timeout(Duration::from_secs(240), task)
        .await
        .expect("test timed out");
    assert!(result.is_ok(), "test failed: {result:?}");
}
