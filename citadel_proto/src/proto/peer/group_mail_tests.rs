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
        id: citadel_types::proto::GroupMessageId([n; 16]),
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

/// Reads and removes `member`'s backlog, as a replay does once it has sent it.
async fn take(
    pers: &PersistenceHandler<StackedRatchet, StackedRatchet>,
    member: u64,
    key: MessageGroupKey,
    max_age: Duration,
    now_ns: i64,
) -> Vec<GroupBroadcast> {
    let held = held(pers, member, key, max_age, now_ns).await.unwrap();
    forget(pers, member, key, &held.sub_keys).await.unwrap();
    held.signals
}

fn bodies(signals: &[GroupBroadcast]) -> Vec<Vec<u8>> {
    signals
        .iter()
        .map(|signal| match signal {
            GroupBroadcast::Message { message, .. } => message.as_ref().to_vec(),
            other => panic!("not a message: {other:?}"),
        })
        .collect()
}

#[tokio::test]
async fn a_backlog_is_bounded_ordered_and_ages_out() {
    let (pers, member) = pers().await;
    let caps = limits(3, 1 << 20);
    let max_age = Duration::from_secs(10);
    for n in 0..5u8 {
        let at = i64::from(n) * SECOND_NS;
        let seq = u64::from(n) + 1;
        let held = hold(&pers, member, KEY, seq, &message(n), &caps, max_age, at).await;
        let expected = if n < 3 {
            Holding::Held
        } else {
            Holding::BacklogFull
        };
        assert_eq!(held.unwrap(), expected, "message {n}");
    }
    let other = MessageGroupKey { cid: 10, mgid: 8 };
    assert!(take(&pers, member, other, max_age, 0).await.is_empty());

    // At 10.5 s only the first message (held at 0 s) is past its 10 s.
    let back = take(&pers, member, KEY, max_age, 10 * SECOND_NS + SECOND_NS / 2).await;
    assert_eq!(
        bodies(&back),
        vec![vec![1u8; 16], vec![2u8; 16]],
        "oldest first, the aged one dropped"
    );
    assert!(take(&pers, member, KEY, max_age, 0).await.is_empty());
}

#[tokio::test]
async fn a_backlog_comes_back_in_the_groups_order_whatever_the_clock_did() {
    let (pers, member) = pers().await;
    let caps = limits(10, 1 << 20);
    let max_age = Duration::from_secs(600);
    // The clock stepped back between the second and third, and two share one tick.
    let held_at = [5, 9, 2, 2];
    for (n, at) in held_at.iter().enumerate() {
        let seq = n as u64 + 1;
        let signal = message(n as u8);
        let _ = hold(&pers, member, KEY, seq, &signal, &caps, max_age, at * SECOND_NS)
            .await
            .unwrap();
    }
    let back = take(&pers, member, KEY, max_age, 10 * SECOND_NS).await;
    assert_eq!(
        bodies(&back),
        (0..4u8).map(|n| vec![n; 16]).collect::<Vec<_>>(),
        "held in seq order, read back in seq order"
    );
}

#[tokio::test]
async fn a_backlog_is_kept_until_it_is_forgotten() {
    let (pers, member) = pers().await;
    let caps = limits(10, 1 << 20);
    let max_age = Duration::from_secs(600);
    let _ = hold(&pers, member, KEY, 1, &message(1), &caps, max_age, 0)
        .await
        .unwrap();
    let first = held(&pers, member, KEY, max_age, 0).await.unwrap();
    // A replay that never reached the stream leaves the backlog where it was.
    let again = held(&pers, member, KEY, max_age, 0).await.unwrap();
    assert_eq!(bodies(&first.signals), bodies(&again.signals));
    forget(&pers, member, KEY, &first.sub_keys).await.unwrap();
    assert!(held(&pers, member, KEY, max_age, 0).await.unwrap().signals.is_empty());
}
