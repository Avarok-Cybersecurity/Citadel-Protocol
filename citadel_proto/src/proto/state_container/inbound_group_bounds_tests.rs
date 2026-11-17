//! A group a peer announces and never sends is reclaimed, and no peer holds more than the cap.
//! Time is tokio's paused clock: the group receiver and the session's expiry state both read it.

use super::super::test_support::state_container;
use super::*;
use crate::proto::session_queue_handler::QueueWorkerResult;
use citadel_io::tokio;
use zerocopy::{AsBytes, FromZeroes};

const PEER_CID: u64 = 20;
const OTHER_PEER_CID: u64 = 30;

fn header_bytes(peer_cid: u64, group_id: u64) -> Vec<u8> {
    let mut header = HdpHeader::new_zeroed();
    header.session_cid.set(peer_cid);
    header.group.set(group_id);
    header.security_level = SecurityLevel::Standard.value();
    header.as_bytes().to_vec()
}

fn one_packet_group(group_id: u64) -> GroupReceiverConfig {
    GroupReceiverConfig {
        packets_needed: 1,
        max_packets_per_wave: 1,
        plaintext_length: 16,
        max_payload_size: 16,
        last_payload_size: 16,
        number_of_full_waves: 1,
        number_of_partial_waves: 0,
        wave_count: 1,
        max_plaintext_wave_length: 16,
        last_plaintext_wave_length: 16,
        packets_in_last_wave: 1,
        header_size_bytes: 0,
        group_id,
        object_id: ObjectId::zero(),
        transfer_type: None,
        empty_transfer: false,
    }
}

fn announce<R: Ratchet>(
    inner: &mut StateContainerInner<R>,
    peer_cid: u64,
    group_id: u64,
) -> Result<RangeInclusive<u32>, NetworkError> {
    let bytes = header_bytes(peer_cid, group_id);
    let header = Ref::<&[u8], HdpHeader>::new(&bytes[..]).expect("header layout");
    inner.on_group_header_received(
        &header,
        one_packet_group(group_id),
        VirtualTargetType::LocalGroupServer {
            session_cid: peer_cid,
        },
    )
}

fn key(peer_cid: u64, group_id: u64) -> GroupKey {
    GroupKey::new(peer_cid, group_id, ObjectId::zero())
}

/// The periodic check's verdict on `key` now. The container's lock is taken per call, as the
/// queue worker takes it, and never held across the clock advancing.
fn check<R: Ratchet>(container: &StateContainer<R>, key: GroupKey) -> QueueWorkerResult {
    inner_mut_state!(container).reclaim_inbound_group_if_silent(key)
}

#[tokio::test(start_paused = true)]
async fn a_group_announced_and_never_sent_is_reclaimed_after_its_deadline() {
    let container = state_container(true, 0).await;
    announce(&mut inner_mut_state!(container), PEER_CID, 1).expect("first header accepted");

    tokio::time::advance(GROUP_EXPIRE_TIME_MS / 2).await;
    assert!(
        matches!(
            check(&container, key(PEER_CID, 1)),
            QueueWorkerResult::Incomplete
        ),
        "held before its deadline"
    );

    tokio::time::advance(GROUP_EXPIRE_TIME_MS).await;
    assert!(matches!(
        check(&container, key(PEER_CID, 1)),
        QueueWorkerResult::Complete
    ));
    assert!(inner_state!(container).inbound_groups.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_silent_group_is_reclaimed_past_the_ceiling_however_busy_the_session() {
    let container = state_container(true, 0).await;
    announce(&mut inner_mut_state!(container), PEER_CID, 1).expect("header accepted");

    // Other traffic keeps arriving the whole time: the session never goes silent.
    let step = GROUP_EXPIRE_TIME_MS / 2;
    let mut waited = std::time::Duration::ZERO;
    while waited <= INBOUND_GROUP_SILENCE_CEILING {
        tokio::time::advance(step).await;
        waited += step;
        inner_state!(container)
            .meta_expiry_state
            .on_event_confirmation();
        if waited <= INBOUND_GROUP_SILENCE_CEILING {
            assert!(
                matches!(
                    check(&container, key(PEER_CID, 1)),
                    QueueWorkerResult::Incomplete
                ),
                "spared while the session is busy, at {waited:?}"
            );
        }
    }
    assert!(matches!(
        check(&container, key(PEER_CID, 1)),
        QueueWorkerResult::Complete
    ));
    assert!(inner_state!(container).inbound_groups.is_empty());
}

#[tokio::test]
async fn a_peer_cannot_hold_more_groups_open_than_the_cap() {
    let container = state_container(true, 0).await;
    let mut inner = inner_mut_state!(container);
    for group_id in 0..1_000u64 {
        let _ = announce(&mut inner, PEER_CID, group_id);
    }
    assert_eq!(
        inner.inbound_groups_open_for(PEER_CID),
        MAX_INBOUND_GROUPS_PER_PEER
    );
    assert_eq!(inner.inbound_groups.len(), MAX_INBOUND_GROUPS_PER_PEER);

    // The cap is per peer: another peer's groups are unaffected.
    announce(&mut inner, OTHER_PEER_CID, 0).expect("another peer's header accepted");
}

#[test]
fn reclaims_is_silence_with_a_silent_session_or_silence_past_the_ceiling() {
    assert!(!reclaims(false, false, false));
    assert!(!reclaims(false, false, true));
    assert!(!reclaims(true, false, false));
    assert!(reclaims(true, false, true));
    assert!(reclaims(true, true, false));
}
