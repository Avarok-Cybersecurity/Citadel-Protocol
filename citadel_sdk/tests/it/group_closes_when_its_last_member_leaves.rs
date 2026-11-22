#![cfg(not(target_family = "wasm"))]
//! A group lives until its last member leaves, and then it is closed: the server holds no such
//! group, and a message sent to it is reported relayed to nobody, for want of a group.
//!
//! ```text
//! O and A befriend; O creates a group inviting A; A joins
//! A leaves; O still owns the group
//! O leaves, the last member; nobody owns the group, and O's send is NotRelayed(UnknownGroup)
//! ```

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use crate::common::group_relay::*;
    use crate::common::group_succession::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    #[tokio::test(flavor = "multi_thread")]
    async fn a_group_closes_when_its_last_member_leaves() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, addr, _server_remote) = probed_server();
        let owner_name = format!("glo_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("glm_{}", &Uuid::new_v4().to_string()[..8]);
        let sync = Arc::new(Barrier::new(2));
        let answer = Arc::new(Mutex::new(None));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (sync, answer) = (sync.clone(), answer.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let options = MessageGroupOptions::default();
                    let (conn, mut channel) =
                        open_group(&remote, addr, (&me, &peer), options).await?;
                    sync.wait().await; // the member left
                    assert_eq!(conn.list_owned_groups().await?, vec![channel.key()]);
                    assert!(
                        leave(&mut channel).await?,
                        "the last member's leave was refused"
                    );
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
            let sync = sync.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, mut channel) =
                        join_group(&remote, addr, (&me, &peer), &mut events).await?;
                    assert!(leave(&mut channel).await?, "the member's leave was refused");
                    assert_eq!(channel.owner(), None);
                    sync.wait().await; // the member left
                    sync.wait().await; // closed
                    assert!(conn.list_owned_groups().await?.is_empty());
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        let answer = answer
            .lock()
            .unwrap()
            .take()
            .expect("the send was answered");
        assert_eq!(
            answer,
            GroupDelivery::NotRelayed(NotRelayed::UnknownGroup),
            "a group whose last member left is still relayed to"
        );
    }
}
