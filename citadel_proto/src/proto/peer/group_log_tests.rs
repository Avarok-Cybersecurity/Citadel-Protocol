use super::*;
use crate::proto::peer::group_log_ops::{read, remove};
use crate::proto::peer::group_sequencer::{digest, GroupOrderBook, Next, Persist};
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_user::backend::BackendType;
use std::time::Duration;

const KEY: MessageGroupKey = MessageGroupKey { cid: 10, mgid: 7 };

type Pers = PersistenceHandler<StackedRatchet, StackedRatchet>;

/// A backend holding one account (the group's owner), the holder of its order.
async fn pers(backend: BackendType) -> (Pers, u64) {
    use crate::proto::peer::mailbox::tests::{register, Manager};
    let manager = Manager::new(backend, None, None, None).await.unwrap();
    let owner = register(&manager, "owner").await;
    (manager.get_persistence_handler().clone(), owner)
}

fn limits(max_messages: u32) -> GroupLogLimits {
    GroupLogLimits {
        max_age: Duration::from_secs(3600),
        max_messages,
        max_bytes: 1 << 30,
        max_message_bytes: GroupLogLimits::MIN_MESSAGE_BYTES,
    }
}

/// Positions one broadcast the way the fan-out does: decide, persist, commit.
async fn position(pers: &Pers, book: &mut GroupOrderBook, holder: u64, frame: &[u8]) -> u64 {
    let id = Some((holder, citadel_types::proto::GroupMessageId::random()));
    let next = book.next(KEY, holder, id, &digest(frame));
    let Next::New { position, persist } = &next else {
        panic!("a fresh id is a new position");
    };
    match persist {
        Persist::Nothing => {}
        Persist::Reserve(through) => {
            let mut order = book.groups[&KEY].clone();
            order.reserved_through = *through;
            write_meta(pers, KEY, &order).await.unwrap();
        }
        Persist::Log => {
            let entry = StoredEntry {
                held_at_ns: 0,
                chain: position.chain.unwrap(),
                id,
                frame: frame.to_vec(),
            };
            append(pers, holder, KEY, position.seq, &entry)
                .await
                .unwrap();
        }
    }
    book.commit(KEY, &next, id, frame.len(), 0);
    position.seq
}

async fn the_count_continues_after_a_restart_on(backend: BackendType) {
    let (pers, owner) = pers(backend).await;
    let mut book = GroupOrderBook::default();
    let _ = position(&pers, &mut book, owner, b"before replay").await;
    let since = book
        .order_mut(KEY, owner)
        .enable_replay(limits(100))
        .unwrap();
    write_meta(&pers, KEY, &book.groups[&KEY]).await.unwrap();
    let mut last = 0;
    for n in 0..4u8 {
        last = position(&pers, &mut book, owner, &[n; 8]).await;
    }
    // A restart: the book is gone, and is read back from the store.
    let reloaded = load(&pers, owner, KEY).await.unwrap().unwrap();
    assert_eq!(reloaded.head, last);
    let log = reloaded.replay.as_ref().unwrap();
    assert_eq!(log.since, since);
    assert_eq!(log.chain, book.groups[&KEY].replay.as_ref().unwrap().chain);
    assert_eq!(
        reloaded.ids.len(),
        4,
        "the message ids are rebuilt from the log"
    );
    let mut book = GroupOrderBook::default();
    let _ = book.groups.insert(KEY, reloaded);
    assert_eq!(position(&pers, &mut book, owner, b"after").await, last + 1);
    let frames: Vec<Vec<u8>> = read(&pers, owner, KEY, &[since, last + 1])
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.frame)
        .collect();
    assert_eq!(frames, vec![vec![0u8; 8], b"after".to_vec()]);
}

#[tokio::test]
async fn a_replay_groups_count_continues_after_a_restart() {
    the_count_continues_after_a_restart_on(BackendType::InMemory).await;
}

#[tokio::test]
async fn a_replay_groups_count_continues_after_a_restart_on_the_filesystem() {
    let dir = std::env::temp_dir().join(format!("citadel-group-log-{}", uuid::Uuid::new_v4()));
    let path = dir.to_str().unwrap().to_string();
    the_count_continues_after_a_restart_on(BackendType::Filesystem(path)).await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_group_without_replay_never_gives_a_number_twice_after_a_restart() {
    let (pers, owner) = pers(BackendType::InMemory).await;
    let mut book = GroupOrderBook::default();
    let mut last = 0;
    for n in 0..3u8 {
        last = position(&pers, &mut book, owner, &[n]).await;
    }
    let reloaded = load(&pers, owner, KEY).await.unwrap().unwrap();
    assert!(reloaded.replay.is_none());
    let mut book = GroupOrderBook::default();
    let _ = book.groups.insert(KEY, reloaded);
    let next = position(&pers, &mut book, owner, b"after").await;
    assert!(next > last, "{next} repeats or goes back from {last}");
}

#[tokio::test]
async fn a_trimmed_log_reads_back_where_it_starts() {
    let (pers, owner) = pers(BackendType::InMemory).await;
    let mut book = GroupOrderBook::default();
    let _ = book.order_mut(KEY, owner).enable_replay(limits(2)).unwrap();
    write_meta(&pers, KEY, &book.groups[&KEY]).await.unwrap();
    for n in 0..4u8 {
        let _ = position(&pers, &mut book, owner, &[n]).await;
    }
    let order = book.groups.get_mut(&KEY).unwrap();
    let (dropped, through) = order.replay.as_ref().unwrap().over_limits(0).unwrap();
    order.trimmed(through);
    write_meta(&pers, KEY, order).await.unwrap();
    remove(&pers, owner, KEY, &dropped).await.unwrap();
    let reloaded = load(&pers, owner, KEY).await.unwrap().unwrap();
    let log = reloaded.replay.as_ref().unwrap();
    assert_eq!((log.earliest(), reloaded.head), (3, 4));
    assert_eq!(log.entries.len(), 2);
}

#[tokio::test]
async fn a_group_never_numbered_has_no_stored_order() {
    let (pers, owner) = pers(BackendType::InMemory).await;
    assert!(load(&pers, owner, KEY).await.unwrap().is_none());
}
