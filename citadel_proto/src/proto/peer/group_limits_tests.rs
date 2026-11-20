use super::*;
use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
use crate::proto::peer::peer_layer::PeerSignal;
use citadel_types::proto::{GroupHierarchyMode, GroupType, MessageGroupOptions};
use citadel_user::serialization::SyncIO;

fn limits(bytes: u32, per_second: u32) -> GroupMessageLimits {
    GroupMessageLimits::new(bytes, per_second).unwrap()
}

const ALICE: u64 = 10;
const BOB: u64 = 20;

#[test]
fn a_group_without_limits_admits_everything() {
    let mut ledger = GroupRateLedger::default();
    let now = Instant::now();
    for _ in 0..1000 {
        assert_eq!(admit(None, &mut ledger, ALICE, 1 << 20, now), Ok(()));
    }
}

#[test]
fn a_message_over_the_size_cap_is_refused_and_not_counted() {
    let caps = limits(16, 1);
    let mut ledger = GroupRateLedger::default();
    let now = Instant::now();
    assert_eq!(
        admit(Some(&caps), &mut ledger, ALICE, 17, now),
        Err(GroupMessageRefusal::TooLarge {
            bytes: 17,
            max_bytes: 16
        })
    );
    assert_eq!(
        admit(Some(&caps), &mut ledger, ALICE, 16, now),
        Ok(()),
        "the refused message spent none of the sender's rate"
    );
}

#[test]
fn each_sender_gets_its_own_rate_within_a_one_second_window() {
    let caps = limits(64, 2);
    let mut ledger = GroupRateLedger::default();
    let start = Instant::now();
    let at = |ms: u64| start + Duration::from_millis(ms);
    assert_eq!(admit(Some(&caps), &mut ledger, ALICE, 1, at(0)), Ok(()));
    assert_eq!(admit(Some(&caps), &mut ledger, ALICE, 1, at(400)), Ok(()));
    let limited = Err(GroupMessageRefusal::RateLimited { max_per_second: 2 });
    assert_eq!(admit(Some(&caps), &mut ledger, ALICE, 1, at(999)), limited);
    assert_eq!(
        admit(Some(&caps), &mut ledger, BOB, 1, at(999)),
        Ok(()),
        "Alice's sends do not spend Bob's rate"
    );
    assert_eq!(
        admit(Some(&caps), &mut ledger, ALICE, 1, at(1000)),
        Ok(()),
        "a new window opens one second after the first"
    );
    assert_eq!(ledger.windows.len(), 2);
    assert_eq!(admit(Some(&caps), &mut ledger, BOB, 1, at(5000)), Ok(()));
    assert_eq!(ledger.windows.len(), 1, "closed windows are forgotten");
}

fn options_without_relay_fields() -> (GroupType, u128, GroupHierarchyMode) {
    (GroupType::Public, 9, GroupHierarchyMode::Flat)
}

fn create(options: MessageGroupOptions) -> PeerSignal {
    PeerSignal::BroadcastConnected {
        session_cid: 1,
        group_broadcast: GroupBroadcast::Create {
            initial_invitees: vec![2],
            options,
        },
    }
}

/// A `Create` carries its relay options; one whose options stop after the hierarchy is refused.
#[test]
fn a_groups_creation_carries_its_relay_options() {
    let options = MessageGroupOptions {
        group_type: GroupType::Public,
        id: 9,
        hierarchy: GroupHierarchyMode::Flat,
        ephemeral: true,
        limits: Some(limits(64, 4)),
    };
    let with = create(options).serialize_to_vector().unwrap();
    match PeerSignal::deserialize_from_vector(&with).unwrap() {
        PeerSignal::BroadcastConnected {
            group_broadcast: GroupBroadcast::Create { options, .. },
            ..
        } => {
            assert!(options.ephemeral);
            assert_eq!(options.limits, Some(limits(64, 4)));
        }
        other => panic!("not a Create: {other:?}"),
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum BroadcastWithoutRelayOptions {
        Create {
            initial_invitees: Vec<u64>,
            options: (GroupType, u128, GroupHierarchyMode),
        },
    }
    let without = BroadcastWithoutRelayOptions::Create {
        initial_invitees: vec![2],
        options: options_without_relay_fields(),
    }
    .serialize_to_vector()
    .unwrap();
    assert!(GroupBroadcast::deserialize_from_vector(&without).is_err());
}

/// Caps that fail validation refuse the `Create`; they are never read as a group without caps.
#[test]
fn a_creation_with_invalid_caps_is_refused() {
    #[derive(serde::Serialize, serde::Deserialize)]
    enum BroadcastWithRawCaps {
        Create {
            initial_invitees: Vec<u64>,
            options: (
                GroupType,
                u128,
                GroupHierarchyMode,
                bool,
                Option<(u32, u32)>,
            ),
        },
    }
    let encode = |caps: (u32, u32)| {
        let (group_type, id, hierarchy) = options_without_relay_fields();
        BroadcastWithRawCaps::Create {
            initial_invitees: vec![2],
            options: (group_type, id, hierarchy, false, Some(caps)),
        }
        .serialize_to_vector()
        .unwrap()
    };
    match GroupBroadcast::deserialize_from_vector(&encode((64, 4))).unwrap() {
        GroupBroadcast::Create { options, .. } => assert_eq!(options.limits, Some(limits(64, 4))),
        other => panic!("not a Create: {other:?}"),
    }
    assert!(GroupBroadcast::deserialize_from_vector(&encode((64, 0))).is_err());
}
