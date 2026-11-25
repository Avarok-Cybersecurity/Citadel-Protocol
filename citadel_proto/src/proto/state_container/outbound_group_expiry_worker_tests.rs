//! The periodic check on an outbound group, on a real state container: it keeps the group while
//! the verdict says so, and once it does not, it ends the transfer and fails the sender's handle
//! by code. Time is tokio's paused clock, which the container, its groups and the session's
//! expiry state all read; nothing here waits on real time.

use super::super::inbound_group_bounds::INBOUND_GROUP_SILENCE_CEILING;
use super::super::test_support::state_container;
use super::super::OutboundTransmitterContainer;
use super::*;
use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::proto::outbound_sender::budgeted_primary_channel;
use crate::proto::packet_crafter::ObjectTransmitter;
use crate::proto::remote::Ticket;
use crate::proto::udp_packet_tests::connected_pair;
use bytes::BufMut;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::scramble::crypt_splitter::{par_scramble_encrypt_group, WaveBinding};
use citadel_io::tokio;
use citadel_io::tokio::sync::mpsc::UnboundedReceiver;
use citadel_types::proto::{ObjectId, TransferType};
use netbeam::time_tracker::TimeTracker;

const PEER_CID: u64 = 20;
const OBJECT: u128 = 7;
const TICKET: Ticket = Ticket(1);

fn key(group_id: u64) -> GroupKey {
    GroupKey::new(PEER_CID, group_id, ObjectId::from(OBJECT))
}

fn file_key() -> FileKey {
    FileKey::new(ObjectId::from(OBJECT))
}

/// Registers group `group_id` of the transfer as the sender does, before its header is sent.
fn register_group(inner: &StateContainerInner<StackedRatchet>, group_id: u64) {
    let (alice, _bob) = connected_pair(SecurityLevel::Standard);
    let sender = par_scramble_encrypt_group::<_, _, _, HDP_HEADER_BYTE_LEN>(
        &[7u8; 512][..],
        SecurityLevel::Standard,
        &alice,
        None,
        HDP_HEADER_BYTE_LEN,
        PEER_CID,
        ObjectId::from(OBJECT),
        group_id,
        TransferType::FileTransfer,
        WaveBinding::Bound,
        |_, _, _, _, buf| buf.put_bytes(0, HDP_HEADER_BYTE_LEN),
    )
    .expect("a group to send");
    let (to_primary_stream, _) = budgeted_primary_channel(usize::MAX, None);
    let transmitter = ObjectTransmitter::new_from_group_sender(
        to_primary_stream,
        sender,
        alice,
        ObjectId::from(OBJECT),
        TICKET,
        SecurityLevel::Standard,
        TimeTracker::new(),
    );
    let container = OutboundTransmitterContainer::new(None, transmitter, 512, 2, 0, TICKET);
    assert!(inner
        .outbound_transmitters
        .insert(key(group_id), container)
        .is_none());
}

/// The sender's handle for the transfer, as `process_outbound_file` registers it.
fn sender_handle(
    inner: &StateContainerInner<StackedRatchet>,
) -> UnboundedReceiver<ObjectTransferStatus> {
    let (tx, rx) = unbounded();
    let _ = inner.file_transfer_handles.insert(file_key(), tx);
    rx
}

fn check(container: &StateContainer<StackedRatchet>, group_id: u64) -> QueueWorkerResult {
    inner_mut_state!(container).check_outbound_group(key(group_id), file_key(), TICKET, None)
}

/// The test container has no kernel listening, so a failed transfer's kernel report cannot be
/// delivered and the worker asks to end the session; what matters here is that it stopped
/// keeping the group.
fn ended(result: QueueWorkerResult) -> bool {
    !matches!(result, QueueWorkerResult::Incomplete)
}

fn failure_code(handle: &mut UnboundedReceiver<ObjectTransferStatus>) -> Option<u16> {
    match handle.try_recv() {
        Ok(ObjectTransferStatus::Failed(failure)) => Some(failure.code),
        _ => None,
    }
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_header_fails_its_transfer_at_the_deadline_and_not_before() {
    let container = state_container(false, 0).await;
    register_group(&inner_state!(container), 0);
    let mut handle = sender_handle(&inner_state!(container));

    tokio::time::advance(FILE_GROUP_HEADER_ACK_DEADLINE - Duration::from_millis(1)).await;
    assert!(matches!(
        check(&container, 0),
        QueueWorkerResult::Incomplete
    ));
    assert!(
        handle.try_recv().is_err(),
        "nothing reported before the deadline"
    );

    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(ended(check(&container, 0)));
    assert_eq!(
        failure_code(&mut handle),
        Some(ErrorCode::FileTransferStalled.as_u16())
    );
    assert!(inner_state!(container).outbound_transmitters.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_header_queued_behind_an_earlier_group_waits_its_full_deadline_once_first_in_line() {
    let container = state_container(false, 0).await;
    register_group(&inner_state!(container), 0);
    tokio::time::advance(Duration::from_millis(1)).await;
    register_group(&inner_state!(container), 1);
    let mut handle = sender_handle(&inner_state!(container));

    // Behind group 0 for four deadlines: kept, its clock restarted at each check.
    for _ in 0..4 {
        tokio::time::advance(FILE_GROUP_HEADER_ACK_DEADLINE).await;
        assert!(matches!(
            check(&container, 1),
            QueueWorkerResult::Incomplete
        ));
    }
    // Group 0 finishes; from the last check, group 1 gets its whole deadline.
    let _ = inner_state!(container)
        .outbound_transmitters
        .remove(&key(0));
    tokio::time::advance(FILE_GROUP_HEADER_ACK_DEADLINE - Duration::from_millis(1)).await;
    assert!(matches!(
        check(&container, 1),
        QueueWorkerResult::Incomplete
    ));
    assert!(handle.try_recv().is_err());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(ended(check(&container, 1)));
    assert_eq!(
        failure_code(&mut handle),
        Some(ErrorCode::FileTransferStalled.as_u16())
    );
}

#[tokio::test(start_paused = true)]
async fn an_answered_group_silent_on_a_busy_session_fails_past_the_ceiling_and_not_before() {
    let container = state_container(false, 0).await;
    register_group(&inner_state!(container), 0);
    inner_state!(container)
        .outbound_transmitters
        .get_mut(&key(0))
        .expect("registered")
        .header_answered = true;
    let mut handle = sender_handle(&inner_state!(container));

    // Other traffic keeps the session busy, so only the ceiling can end the group.
    let busy = |container: &StateContainer<StackedRatchet>| {
        inner_state!(container)
            .meta_expiry_state
            .on_event_confirmation()
    };
    tokio::time::advance(INBOUND_GROUP_SILENCE_CEILING).await;
    busy(&container);
    assert!(matches!(
        check(&container, 0),
        QueueWorkerResult::Incomplete
    ));
    assert!(handle.try_recv().is_err());

    tokio::time::advance(Duration::from_millis(1)).await;
    busy(&container);
    assert!(ended(check(&container, 0)));
    assert_eq!(
        failure_code(&mut handle),
        Some(ErrorCode::FileTransferStalled.as_u16())
    );
}
