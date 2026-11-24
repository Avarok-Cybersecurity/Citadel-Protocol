use super::*;
use crate::proto::peer::group_sequencer::{digest, GroupOrderBook, Next, Persist};
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_io::tokio;
use citadel_user::backend::BackendType;

const KEY: MessageGroupKey = MessageGroupKey { cid: 10, mgid: 7 };

type Pers = PersistenceHandler<StackedRatchet, StackedRatchet>;

/// A backend holding one account (the group's owner), the holder of its order.
async fn pers(backend: BackendType) -> (Pers, u64) {
    use crate::proto::peer::mailbox::tests::{register, Manager};
    let manager = Manager::new(backend, None, None, None).await.unwrap();
    let owner = register(&manager, "owner").await;
    (manager.get_persistence_handler().clone(), owner)
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
async fn a_group_never_numbered_has_no_stored_order() {
    let (pers, owner) = pers(BackendType::InMemory).await;
    assert!(load(&pers, owner, KEY).await.unwrap().is_none());
}
