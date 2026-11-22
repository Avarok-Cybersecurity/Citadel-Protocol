#![cfg(not(target_family = "wasm"))]
//! An owner that moves to a new device with its recovery phrase keeps its group: the new device
//! reads what was sent while the owner was away, is told its state came from the account's
//! backup, replaces the owner's leaf with a Commit every member applies, and the group reads on.
//!
//! ```text
//! O and M register with phrases; O's first device (D1) logs in; O and M befriend
//! D1 creates a group inviting M; M joins; D1 sends "hello", so the server has kept O's sealed
//! state with M in it
//! D1 disconnects; M sends "while-away", which the server holds for O
//! O recovers on a second device (D2) with its phrase, sets a password and logs in
//! D2 must read "while-away", be told its state came from the backup, and commit a new leaf
//! that the server waits on M to apply; then M must read D2's "after", and D2 M's "back"
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_device::*;
    use crate::common::group_epoch::{befriend, run_trio};
    use crate::common::group_relay::*;
    use crate::common::pq::{login, poisoned_argon, pq_settings, username, PASSWORD};
    use crate::common::recovery::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::{oneshot, Barrier};
    use citadel_proto::test_hooks::observe_commit_gates;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Seen {
        /// The owner's account and its group, once D1 has them.
        group: Mutex<Option<(u64, MessageGroupKey)>>,
        source: Mutex<Option<GroupStateSource>>,
        /// Whether, after D2 logged in, the server waited on M to apply an owner's Commit.
        leaf_replaced: AtomicBool,
        read_away: AtomicBool,
        read_after: AtomicBool,
        read_back: AtomicBool,
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_recovered_owner_keeps_its_group_and_replaces_its_leaf() {
        citadel_logging::setup_log();
        let (server, addr, server_remote) = probed_server_with(|builder| {
            let _ = builder
                .with_server_misc_settings(pq_settings())
                .with_server_argon_settings(poisoned_argon());
        });
        let (owner_name, member_name) = (username("god"), username("gom"));
        let (root, new_root): (Root, Root) = Default::default();
        let (phrase_tx, phrase_rx) = oneshot::channel::<RecoveryPhrase>();
        let (befriending, owner_away) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        let joined = Arc::new(Barrier::new(2));
        let (mailed, back_in) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        let done = Arc::new(Barrier::new(3));
        let seen = Arc::new(Seen::default());

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (befriending, owner_away, mailed) =
                (befriending.clone(), owner_away.clone(), mailed.clone());
            let (back_in, done, seen) = (back_in.clone(), done.clone(), seen.clone());
            let joined = joined.clone();
            let server_remote = server_remote.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let _ = with_phrase(&remote, addr, &me).await?;
                    let conn = login(&remote, &me, PASSWORD).await?;
                    befriending.wait().await;
                    befriend(&conn, conn.cid, &me, &peer).await?;
                    befriending.wait().await;
                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut channel = next_group_channel(&mut events, "member").await;
                    joined.wait().await;
                    owner_away.wait().await;

                    let (owner_cid, _) = seen.group.lock().unwrap().expect("the owner's group");
                    until_offline(server_of(&server_remote), owner_cid).await;
                    channel
                        .send_message(SecBuffer::from(b"while-away".to_vec()))
                        .await?;
                    let answer = next_send_answer(&mut channel).await;
                    log::info!(target: "citadel", "[member] answer to while-away: {answer:?}");
                    mailed.wait().await;

                    back_in.wait().await;
                    let (tx, mut rx) = channel.split();
                    let reading = async {
                        seen.read_after
                            .store(read(&mut rx, "after").await, Ordering::SeqCst)
                    };
                    let (sent, ()) =
                        futures::join!(send_until_read(&tx, "back", &seen.read_back), reading);
                    sent?;
                    done.wait().await;
                    conn.shutdown_kernel().await
                },
            )
        };

        let first_device = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (befriending, owner_away, done) =
                (befriending.clone(), owner_away.clone(), done.clone());
            let joined = joined.clone();
            let (seen, server_remote, root) = (seen.clone(), server_remote.clone(), root.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _: Events| async move {
                    let phrase = with_phrase(&remote, addr, &me).await?;
                    *root.lock().unwrap() = Some(*phrase.seed().as_bytes());
                    let _ = phrase_tx.send(phrase);
                    let conn = login(&remote, &me, PASSWORD).await?;
                    befriending.wait().await;
                    befriend(&conn, conn.cid, &me, &peer).await?;
                    befriending.wait().await;
                    let mut channel = conn.create_group(Some(vec![peer.clone().into()])).await?;
                    let key = channel.key();
                    joined.wait().await;
                    // Answered after the state kept for the member's join, on the same stream.
                    channel
                        .send_message(SecBuffer::from(b"hello".to_vec()))
                        .await?;
                    let _ = next_send_answer(&mut channel).await;
                    until_state_kept(server_of(&server_remote), conn.cid, key).await;
                    *seen.group.lock().unwrap() = Some((conn.cid, key));
                    conn.disconnect().await?;
                    owner_away.wait().await;
                    drop(channel);
                    done.wait().await;
                    remote.shutdown().await
                },
            )
        };

        let second_device = {
            let me = owner_name.clone();
            let (mailed, back_in, done, root) = (
                mailed.clone(),
                back_in.clone(),
                done.clone(),
                new_root.clone(),
            );
            let seen = seen.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let phrase = phrase_rx.await.expect("the first device registered");
                    mailed.wait().await;
                    let (_, key) = seen.group.lock().unwrap().expect("the owner's group");
                    let _ = recover(&remote, addr, &me, &phrase).await?;
                    let session = phrase_session(&remote, &me, &phrase).await?;
                    session
                        .set_password(NEW_PASSWORD, SignInFactors::default())
                        .await?;
                    session.disconnect().await?;
                    *root.lock().unwrap() = Some(*phrase.seed().as_bytes());
                    let mut gates = observe_commit_gates();
                    let conn = login(&remote, &me, NEW_PASSWORD).await?;
                    let channel = next_group_channel(&mut events, "second device").await;
                    let (tx, mut rx) = channel.split();
                    seen.read_away
                        .store(read(&mut rx, "while-away").await, Ordering::SeqCst);
                    *seen.source.lock().unwrap() = restored(&mut rx).await;
                    let replaced = tokio::time::timeout(REJOIN_DEADLINE, async {
                        while let Some(gate) = gates.recv().await {
                            if gate.key == key && !gate.awaiting.is_empty() {
                                return true;
                            }
                        }
                        false
                    })
                    .await
                    .unwrap_or(false);
                    seen.leaf_replaced.store(replaced, Ordering::SeqCst);
                    back_in.wait().await;
                    let reading = async {
                        seen.read_back
                            .store(read(&mut rx, "back").await, Ordering::SeqCst)
                    };
                    let (sent, ()) =
                        futures::join!(send_until_read(&tx, "after", &seen.read_after), reading);
                    sent?;
                    done.wait().await;
                    conn.shutdown_kernel().await
                },
            )
        };

        run_trio(
            server,
            client_node(member),
            device(first_device, root.clone()),
            device(second_device, new_root),
        )
        .await;
        assert!(
            seen.read_away.load(Ordering::SeqCst),
            "the new device did not read what was sent while the owner was away"
        );
        assert_eq!(
            *seen.source.lock().unwrap(),
            Some(GroupStateSource::Backup),
            "the new device was not told its group came back from the account's backup"
        );
        assert!(
            seen.leaf_replaced.load(Ordering::SeqCst),
            "the new device did not commit a new leaf for the owner"
        );
        assert!(
            seen.read_after.load(Ordering::SeqCst),
            "the member did not read what the owner sent from its new leaf"
        );
        assert!(
            seen.read_back.load(Ordering::SeqCst),
            "the new device did not read what the member sent"
        );
    }
}
