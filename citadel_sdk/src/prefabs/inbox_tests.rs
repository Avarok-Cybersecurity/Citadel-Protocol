//! An inbox nobody reads stays bounded and answers what it cannot deliver.

use super::*;
use citadel_proto::prelude::{ObjectTransferOrientation, VirtualObjectMetadata};
use citadel_types::proto::{ObjectId, TransferType};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct Counted(Arc<AtomicUsize>);

impl Unclaimed for Counted {
    fn dispose(self) {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counted() -> (Counted, Arc<AtomicUsize>) {
    let disposed = Arc::new(AtomicUsize::new(0));
    (Counted(disposed.clone()), disposed)
}

#[test]
fn an_inbox_nobody_claims_keeps_a_bounded_backlog_and_disposes_of_the_rest() {
    let (tx, claim) = inbox::<Counted>();
    let (item, disposed) = counted();
    for _ in 0..100 {
        tx.deliver(item.clone());
    }
    assert_eq!(disposed.load(Ordering::SeqCst), 100 - UNCLAIMED_BACKLOG);

    let mut rx = claim.take().expect("first claim");
    let mut flushed = 0;
    while rx.try_recv().is_ok() {
        flushed += 1;
    }
    assert_eq!(flushed, UNCLAIMED_BACKLOG);
    assert!(claim.take().is_none(), "a receiver is taken once");
}

#[test]
fn dropping_every_claim_disposes_of_the_backlog_and_all_later_events() {
    let (tx, claim) = inbox::<Counted>();
    let second = claim.clone();
    let (item, disposed) = counted();
    tx.deliver(item.clone());
    drop(claim);
    assert_eq!(
        disposed.load(Ordering::SeqCst),
        0,
        "one claim is still held"
    );
    drop(second);
    assert_eq!(disposed.load(Ordering::SeqCst), 1);
    tx.deliver(item);
    assert_eq!(disposed.load(Ordering::SeqCst), 2);
}

#[test]
fn a_taken_receiver_keeps_receiving_after_its_claim_drops_and_disposes_once_dropped() {
    let (tx, claim) = inbox::<Counted>();
    let mut rx = claim.take().unwrap();
    drop(claim);
    let (item, disposed) = counted();
    tx.deliver(item.clone());
    assert!(rx.try_recv().is_ok());
    drop(rx);
    tx.deliver(item);
    assert_eq!(disposed.load(Ordering::SeqCst), 1);
}

#[test]
fn an_unclaimed_file_offer_is_declined() {
    let (answer_tx, mut answer_rx) = citadel_io::tokio::sync::oneshot::channel();
    let (offer, _status) = ObjectTransferHandler::new(
        1,
        2,
        VirtualObjectMetadata {
            name: "offer".into(),
            date_created: String::new(),
            author: String::new(),
            plaintext_length: 0,
            group_count: 0,
            object_id: ObjectId(0),
            cid: 1,
            transfer_type: TransferType::FileTransfer,
        },
        ObjectTransferOrientation::Receiver {
            is_revfs_pull: false,
        },
        Some(answer_tx),
    );
    let (tx, claim) = inbox::<ObjectTransferHandler>();
    drop(claim);
    tx.deliver(offer);
    assert_eq!(
        answer_rx.try_recv(),
        Ok(false),
        "the sender must hear a decline"
    );
}
