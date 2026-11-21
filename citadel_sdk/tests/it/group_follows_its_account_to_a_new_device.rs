#![cfg(not(target_family = "wasm"))]
//! An account that moves to a new device with its recovery phrase takes its groups along: the
//! new device reads what was sent to the group while the account was away, sends to it, and,
//! once its leaf is replaced, reads what the owner sends after that.
//!
//! ```text
//! O and M register with phrases; M's first device (D1) logs in; O and M befriend
//! O creates a group inviting M; D1 joins; the server keeps M's sealed state
//! D1 disconnects; O sends "while-away", which the server holds for M
//! M recovers on a second device (D2) with its phrase, sets a password and logs in
//! D2 must read "while-away"; then O must read D2's "back", and D2 O's "after"
//! ```
//!
//! Each device derives the account's key from the phrase's seed, as an application does; the
//! server never holds it.

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
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    #[tokio::test(flavor = "multi_thread")]
    async fn a_recovered_account_reads_and_sends_to_its_group_from_the_new_device() {
        citadel_logging::setup_log();
        let (server, addr, server_remote) = probed_server_with(|builder| {
            let _ = builder
                .with_server_misc_settings(pq_settings())
                .with_server_argon_settings(poisoned_argon());
        });
        let (owner_name, member_name) = (username("gdo"), username("gdm"));
        let (root, new_root): (Root, Root) = Default::default();
        let (phrase_tx, phrase_rx) = oneshot::channel::<RecoveryPhrase>();
        let (befriending, member_away) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        let (mailed, back_in) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        let done = Arc::new(Barrier::new(3));
        let (read_away, read_back, read_after) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let member_cid = Arc::new(Mutex::new(None::<(u64, MessageGroupKey)>));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (befriending, member_away, mailed, back_in, done) = (
                befriending.clone(),
                member_away.clone(),
                mailed.clone(),
                back_in.clone(),
                done.clone(),
            );
            let (member_cid, server_remote) = (member_cid.clone(), server_remote.clone());
            let (read_back, read_after) = (read_back.clone(), read_after.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _: Events| async move {
                    let _ = with_phrase(&remote, addr, &me).await?;
                    let conn = login(&remote, &me, PASSWORD).await?;
                    befriending.wait().await;
                    befriend(&conn, conn.cid, &me, &peer).await?;
                    befriending.wait().await;
                    let mut channel = conn.create_group(Some(vec![peer.clone().into()])).await?;
                    member_away.wait().await;

                    let (cid, key) = member_cid
                        .lock()
                        .unwrap()
                        .expect("the member said who it is");
                    assert_eq!(key, channel.key());
                    let server = server_of(&server_remote);
                    until_offline(server, cid).await;
                    channel
                        .send_message(SecBuffer::from(b"while-away".to_vec()))
                        .await?;
                    let answer = next_send_answer(&mut channel).await;
                    log::info!(target: "citadel", "[owner] answer to while-away: {answer:?}");
                    mailed.wait().await;

                    back_in.wait().await;
                    let (tx, mut rx) = channel.split();
                    let reading =
                        async { read_back.store(read(&mut rx, "back").await, Ordering::SeqCst) };
                    let (sent, ()) =
                        futures::join!(send_until_read(&tx, "after", &read_after), reading);
                    sent?;
                    done.wait().await;
                    conn.shutdown_kernel().await
                },
            )
        };

        let first_device = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (befriending, member_away, done) =
                (befriending.clone(), member_away.clone(), done.clone());
            let (member_cid, server_remote, root) =
                (member_cid.clone(), server_remote.clone(), root.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let phrase = with_phrase(&remote, addr, &me).await?;
                    *root.lock().unwrap() = Some(*phrase.seed().as_bytes());
                    let _ = phrase_tx.send(phrase);
                    let conn = login(&remote, &me, PASSWORD).await?;
                    befriending.wait().await;
                    befriend(&conn, conn.cid, &me, &peer).await?;
                    befriending.wait().await;
                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let channel = next_group_channel(&mut events, "first device").await;
                    let key = channel.key();
                    until_state_kept(server_of(&server_remote), conn.cid, key).await;
                    *member_cid.lock().unwrap() = Some((conn.cid, key));
                    conn.disconnect().await?;
                    member_away.wait().await;
                    drop(channel);
                    done.wait().await;
                    remote.shutdown().await
                },
            )
        };

        let second_device = {
            let me = member_name.clone();
            let (mailed, back_in, done, root) = (
                mailed.clone(),
                back_in.clone(),
                done.clone(),
                new_root.clone(),
            );
            let (read_away, read_back, read_after) =
                (read_away.clone(), read_back.clone(), read_after.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let phrase = phrase_rx.await.expect("the first device registered");
                    mailed.wait().await;
                    let _ = recover(&remote, addr, &me, &phrase).await?;
                    let session = phrase_session(&remote, &me, &phrase).await?;
                    session
                        .set_password(NEW_PASSWORD, SignInFactors::default())
                        .await?;
                    session.disconnect().await?;
                    // This device learns the account's key from the phrase it was given.
                    *root.lock().unwrap() = Some(*phrase.seed().as_bytes());
                    let conn = login(&remote, &me, NEW_PASSWORD).await?;
                    let channel = next_group_channel(&mut events, "second device").await;
                    let (tx, mut rx) = channel.split();
                    read_away.store(read(&mut rx, "while-away").await, Ordering::SeqCst);
                    back_in.wait().await;
                    if read_away.load(Ordering::SeqCst) {
                        let reading = async {
                            read_after.store(read(&mut rx, "after").await, Ordering::SeqCst)
                        };
                        let (sent, ()) =
                            futures::join!(send_until_read(&tx, "back", &read_back), reading);
                        sent?;
                    }
                    done.wait().await;
                    conn.shutdown_kernel().await
                },
            )
        };

        run_trio(
            server,
            client_node(owner),
            device(first_device, root.clone()),
            device(second_device, new_root),
        )
        .await;
        assert!(
            read_away.load(Ordering::SeqCst),
            "the new device did not read what was sent while the account was away"
        );
        assert!(
            read_back.load(Ordering::SeqCst),
            "the owner did not read what the new device sent"
        );
        assert!(
            read_after.load(Ordering::SeqCst),
            "the new device did not read what the owner sent after its leaf was replaced"
        );
    }
}
