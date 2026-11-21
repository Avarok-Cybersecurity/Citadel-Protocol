use super::*;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_types::crypto::SecBuffer;
use citadel_user::backend::BackendType;

const SECOND_NS: i64 = 1_000_000_000;

fn limits(messages: usize, bytes: usize) -> GroupMailLimits {
    GroupMailLimits {
        max_age: Duration::from_secs(60),
        max_messages: NonZeroUsize::new(messages).unwrap(),
        max_bytes: NonZeroUsize::new(bytes).unwrap(),
    }
}

fn message(n: u8) -> GroupBroadcast {
    GroupBroadcast::Message {
        sender: 10,
        key: KEY,
        message: SecBuffer::from(vec![n; 16]),
    }
}

const KEY: MessageGroupKey = MessageGroupKey { cid: 10, mgid: 7 };

/// A backend holding one account, whose cid a backlog is kept under.
async fn pers() -> (PersistenceHandler<StackedRatchet, StackedRatchet>, u64) {
    use crate::proto::peer::mailbox::tests::{register, Manager};
    let manager = Manager::new(BackendType::InMemory, None, None, None)
        .await
        .unwrap();
    let member = register(&manager, "away").await;
    (manager.get_persistence_handler().clone(), member)
}

#[test]
fn a_group_may_ask_for_less_retention_never_more() {
    let caps = limits(1, 1);
    assert_eq!(caps.max_age_for(None), Duration::from_secs(60));
    assert_eq!(
        caps.max_age_for(Some(Duration::from_secs(5))),
        Duration::from_secs(5)
    );
    assert_eq!(
        caps.max_age_for(Some(Duration::from_secs(600))),
        Duration::from_secs(60)
    );
}

#[test]
fn messages_past_a_cap_are_not_held_but_control_always_is() {
    let entry = |bytes, is_message| HeldEntry {
        sub_key: String::new(),
        held_at_ns: 0,
        bytes,
        is_message,
    };
    let caps = limits(2, 100);
    let two = [entry(10, true), entry(10, true)];
    assert_eq!(admit(&two[..1], 10, true, &caps), Holding::Held);
    assert_eq!(admit(&two, 10, true, &caps), Holding::BacklogFull);
    assert_eq!(admit(&two, 10, false, &caps), Holding::Held);
    assert_eq!(
        admit(&[entry(95, false)], 10, true, &caps),
        Holding::BacklogFull
    );
}

#[tokio::test]
async fn a_backlog_is_bounded_ordered_and_ages_out() {
    let (pers, member) = pers().await;
    let caps = limits(3, 1 << 20);
    let max_age = Duration::from_secs(10);
    for n in 0..5u8 {
        let at = i64::from(n) * SECOND_NS;
        let held = hold(&pers, member, KEY, &message(n), &caps, max_age, at).await;
        let expected = if n < 3 {
            Holding::Held
        } else {
            Holding::BacklogFull
        };
        assert_eq!(held.unwrap(), expected, "message {n}");
    }
    let other = MessageGroupKey { cid: 10, mgid: 8 };
    assert!(take(&pers, member, other, max_age, 0)
        .await
        .unwrap()
        .is_empty());

    // At 10.5 s only the first message (held at 0 s) is past its 10 s.
    let back = take(&pers, member, KEY, max_age, 10 * SECOND_NS + SECOND_NS / 2)
        .await
        .unwrap();
    let bytes: Vec<Vec<u8>> = back
        .iter()
        .map(|signal| match signal {
            GroupBroadcast::Message { message, .. } => message.as_ref().to_vec(),
            other => panic!("not a message: {other:?}"),
        })
        .collect();
    assert_eq!(
        bytes,
        vec![vec![1u8; 16], vec![2u8; 16]],
        "oldest first, the aged one dropped"
    );
    assert!(take(&pers, member, KEY, max_age, 0)
        .await
        .unwrap()
        .is_empty());
}
