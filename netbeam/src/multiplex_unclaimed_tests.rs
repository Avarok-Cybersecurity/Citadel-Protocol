//! A peer can only fill memory for subscription ids this side opened, and only up to a bound
//! until this side claims them.

use crate::multiplex::{MultiplexedConn, MultiplexedPacket, UNCLAIMED_BUFFER_LIMIT};
use crate::reliable_conn::ReliableOrderedStreamToTarget;
use crate::sync::subscription::{Subscribable, SubscriptionBiStream};
use crate::sync::wire::WireRevision;
use crate::sync::{RelativeNodeType, SymmetricConvID};
use async_trait::async_trait;
use bytes::Bytes;
use citadel_io::tokio;

const FRAME: usize = 1024;

/// Nothing is read from it: each test feeds the multiplexer's reader path directly.
struct Silent;

#[async_trait]
impl ReliableOrderedStreamToTarget for Silent {
    async fn send_to_peer(&self, _input: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        std::future::pending().await
    }
}

fn conn(wire: WireRevision) -> MultiplexedConn {
    MultiplexedConn::new(RelativeNodeType::Receiver, Silent, wire)
}

fn frame(id: u64) -> Vec<u8> {
    bincode::serialize(&MultiplexedPacket::<SymmetricConvID>::ApplicationLayer {
        id: id.into(),
        payload: vec![0xAB; FRAME],
    })
    .unwrap()
}

/// Feeds frames for `id` until one is refused; returns how many were accepted.
async fn accepted_frames(conn: &MultiplexedConn, id: u64, offered: usize) -> usize {
    let frame = frame(id);
    for accepted in 0..offered {
        if conn.forward_packet(&frame).await.is_err() {
            return accepted;
        }
    }
    offered
}

#[tokio::test]
async fn frames_for_an_id_never_opened_are_refused() {
    let conn = conn(WireRevision::Exchanged);
    assert_eq!(accepted_frames(&conn, 7, 4096).await, 0);
    assert!(conn.subscriptions().read().is_empty());
}

#[tokio::test]
async fn an_unclaimed_id_buffers_at_most_the_limit_and_is_then_refused() {
    let conn = conn(WireRevision::Exchanged);
    let id = SymmetricConvID::from(7);
    conn.reserve(id);
    let accepted = accepted_frames(&conn, 7, 4096).await;
    assert_eq!(accepted, UNCLAIMED_BUFFER_LIMIT / FRAME);
    assert!(
        conn.claim_reserved(id).is_none(),
        "the refused id could still be claimed, with a gap in its stream"
    );
}

/// The ids the count-paired wire opens without asking are bounded the same way.
#[tokio::test]
async fn a_pre_reserved_id_nobody_claims_is_bounded() {
    let conn = conn(WireRevision::CountPaired);
    assert_eq!(
        accepted_frames(&conn, 1, 4096).await,
        UNCLAIMED_BUFFER_LIMIT / FRAME
    );
}

/// The bound is on what waits for a claim, not on a subscription its owner reads.
#[tokio::test]
async fn a_claimed_id_is_not_bounded() {
    let conn = conn(WireRevision::Exchanged);
    let id = SymmetricConvID::from(7);
    conn.reserve(id);
    let sub = conn.claim_reserved(id).unwrap();
    let offered = 2 * UNCLAIMED_BUFFER_LIMIT / FRAME;
    assert_eq!(accepted_frames(&conn, 7, offered).await, offered);
    assert_eq!(sub.id(), id);
}
