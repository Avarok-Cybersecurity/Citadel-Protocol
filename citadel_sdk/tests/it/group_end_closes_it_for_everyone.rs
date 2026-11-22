#![cfg(not(target_family = "wasm"))]
//! An owner that closes its group (`End`) closes it for everyone at once: each member is told,
//! nobody owns it, and a message sent to it is reported relayed to nobody, for want of a group.
//!
//! ```text
//! O and A befriend; O creates a group inviting A; A joins
//! O ends the group; A is told it is out; nobody owns the group; O's send is
//!   NotRelayed(UnknownGroup)
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use crate::common::group_succession::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    #[tokio::test(flavor = "multi_thread")]
    async fn an_owner_that_ends_its_group_closes_it_for_everyone() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, addr, _server_remote) = probed_server();
        let owner_name = format!("geo_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gem_{}", &Uuid::new_v4().to_string()[..8]);
        let sync = Arc::new(Barrier::new(2));
        let answer = Arc::new(Mutex::new(None));
        let member_told = Arc::new(AtomicBool::new(false));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (sync, answer) = (sync.clone(), answer.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let options = MessageGroupOptions::default();
                    let (conn, mut channel) =
                        open_group(&remote, addr, (&me, &peer), options).await?;
                    channel.end().await?;
                    let ended = next_on_channel(&mut channel, "EndResponse", |event| match event {
                        GroupBroadcast::EndResponse { success, .. } => Some(*success),
                        _ => None,
                    })
                    .await;
                    assert!(ended, "the owner's End was refused");
                    assert_eq!(channel.owner(), None);
                    assert!(conn.list_owned_groups().await?.is_empty());
                    let delivery = send_after_leaving(&channel, &mut events).await?;
                    *answer.lock().unwrap() = Some(delivery);
                    sync.wait().await; // closed
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (sync, member_told) = (sync.clone(), member_told.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, mut channel) =
                        join_group(&remote, addr, (&me, &peer), &mut events).await?;
                    let reason = disconnected(&mut channel).await;
                    assert_eq!(reason, GroupEndReason::ClosedByOwner);
                    member_told.store(true, Ordering::SeqCst);
                    assert_eq!(channel.owner(), None);
                    sync.wait().await; // closed
                    assert!(conn.list_owned_groups().await?.is_empty());
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        assert!(
            member_told.load(Ordering::SeqCst),
            "the member was not told"
        );
        let answer = answer
            .lock()
            .unwrap()
            .take()
            .expect("the send was answered");
        assert_eq!(
            answer,
            GroupDelivery::NotRelayed(NotRelayed::UnknownGroup),
            "an ended group is still relayed to"
        );
    }
}
