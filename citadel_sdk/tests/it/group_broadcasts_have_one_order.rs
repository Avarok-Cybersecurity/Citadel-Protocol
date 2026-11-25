#![cfg(not(target_family = "wasm"))]
//! Every member of a group sees its broadcasts at the same positions, in increasing order, and a
//! sender learns its message's position before anything positioned after it.
//!
//! ```text
//! one order:  O and M each send 25 messages at once; each records, in arrival order, its own
//!             answers' positions and the other's messages' positions. Each record must
//!             increase, and both must give every position to the same message.
//! answer first: the server takes 1 s longer over its answer to O's message; M sends as soon as
//!             it reads O's. O must read its answer before M's message.
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_proto::test_hooks::slow_group_answers_to;
    use citadel_sdk::prelude::*;
    use futures::StreamExt;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use uuid::Uuid;

    const EACH: usize = 25;

    /// One thing a member read on its channel, in the order it read them.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Read {
        Answer {
            seq: u64,
            id: GroupMessageId,
        },
        Message {
            seq: u64,
            id: GroupMessageId,
            text: String,
        },
    }

    impl Read {
        fn seq(&self) -> u64 {
            match self {
                Read::Answer { seq, .. } | Read::Message { seq, .. } => *seq,
            }
        }
        fn id(&self) -> GroupMessageId {
            match self {
                Read::Answer { id, .. } | Read::Message { id, .. } => *id,
            }
        }
    }

    type Log = Arc<Mutex<Vec<Read>>>;

    /// Reads `channel` until `done` says the log is complete.
    async fn read_until(
        channel: &mut GroupChannelRecvHalf,
        log: &Log,
        done: impl Fn(&[Read]) -> bool,
    ) {
        while !done(&log.lock().unwrap()) {
            let read = match channel.next().await {
                Some(GroupBroadcastPayload::Message {
                    payload,
                    id,
                    position,
                    ..
                }) => Read::Message {
                    seq: position.seq,
                    id,
                    text: String::from_utf8_lossy(payload.as_ref()).to_string(),
                },
                Some(GroupBroadcastPayload::Event {
                    payload:
                        GroupBroadcast::MessageResponse {
                            id,
                            position,
                            delivery,
                            ..
                        },
                }) => {
                    let position = position.unwrap_or_else(|| panic!("not relayed: {delivery:?}"));
                    Read::Answer {
                        seq: position.seq,
                        id,
                    }
                }
                Some(_) => continue,
                None => panic!("the group channel closed"),
            };
            log.lock().unwrap().push(read);
        }
    }

    fn counts(log: &[Read]) -> (usize, usize) {
        let answers = log
            .iter()
            .filter(|r| matches!(r, Read::Answer { .. }))
            .count();
        (answers, log.len() - answers)
    }

    /// Runs O and M, each sending `send` then reading until `done`, and returns their logs.
    async fn run(
        send: fn(GroupChannelSendHalf, Log, bool) -> futures::future::BoxFuture<'static, ()>,
        done: fn(&[Read]) -> bool,
        slow_owner_answers: bool,
    ) -> (Vec<Read>, Vec<Read>) {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, server_addr, _server_remote) = probed_server();
        let owner_name = format!("goo_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gom_{}", &Uuid::new_v4().to_string()[..8]);
        let finished = Arc::new(Barrier::new(2));
        let logs: [Log; 2] = Default::default();
        let side = |is_owner: bool| {
            let (me, peer) = match is_owner {
                true => (owner_name.clone(), member_name.clone()),
                false => (member_name.clone(), owner_name.clone()),
            };
            let (finished, log) = (finished.clone(), logs[usize::from(!is_owner)].clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, channel) = if is_owner {
                        open_group(
                            &remote,
                            server_addr,
                            (&me, &peer),
                            MessageGroupOptions::default(),
                        )
                        .await?
                    } else {
                        join_group(&remote, server_addr, (&me, &peer), &mut events).await?
                    };
                    let _slow = (is_owner && slow_owner_answers)
                        .then(|| slow_group_answers_to(conn.cid, Duration::from_secs(1)));
                    let (tx, mut rx) = channel.split();
                    let sending = tokio::spawn(send(tx.clone(), log.clone(), is_owner));
                    read_until(&mut rx, &log, done).await;
                    sending.await.unwrap();
                    finished.wait().await;
                    drop((tx, rx));
                    conn.shutdown_kernel().await
                },
            )
        };
        let (owner, member) = (side(true), side(false));
        run_pair(server, client_node(owner), client_node(member)).await;
        let [o, m] = logs;
        let (o, m) = (o.lock().unwrap().clone(), m.lock().unwrap().clone());
        (o, m)
    }

    fn increasing(who: &str, log: &[Read]) {
        let seqs: Vec<u64> = log.iter().map(Read::seq).collect();
        assert!(
            seqs.windows(2).all(|w| w[0] < w[1]),
            "{who} read positions out of order: {seqs:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn every_member_sees_the_same_positions_in_increasing_order() {
        let (owner, member) = run(
            |tx, _, is_owner| {
                Box::pin(async move {
                    let me = if is_owner { "o" } else { "m" };
                    for idx in 0..EACH {
                        let text = format!("{me}-{idx}");
                        tx.send_message(SecBuffer::from(text.into_bytes()))
                            .await
                            .unwrap();
                    }
                })
            },
            |log| counts(log) == (EACH, EACH),
            false,
        )
        .await;
        increasing("the owner", &owner);
        increasing("the member", &member);
        let by_seq = |log: &[Read]| -> BTreeMap<u64, GroupMessageId> {
            log.iter().map(|r| (r.seq(), r.id())).collect()
        };
        assert_eq!(by_seq(&owner).len(), 2 * EACH, "a position was given twice");
        assert_eq!(
            by_seq(&owner),
            by_seq(&member),
            "the members disagree on the order"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_sender_reads_its_answer_before_what_was_positioned_after_it() {
        let (owner, _member) = run(
            |tx, log, is_owner| {
                Box::pin(async move {
                    if !is_owner {
                        // The member sends once it has read the owner's message.
                        while counts(&log.lock().unwrap()).1 == 0 {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                    let text = if is_owner { "first" } else { "second" };
                    tx.send_message(SecBuffer::from(text.as_bytes().to_vec()))
                        .await
                        .unwrap();
                })
            },
            |log| counts(log) == (1, 1),
            true,
        )
        .await;
        assert!(
            matches!(owner.as_slice(), [Read::Answer { .. }, Read::Message { text, .. }] if text == "second"),
            "the owner read a broadcast positioned after its message before its answer: {owner:?}"
        );
        increasing("the owner", &owner);
    }
}
