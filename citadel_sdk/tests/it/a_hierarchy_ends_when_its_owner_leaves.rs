#![cfg(not(target_family = "wasm"))]
//! A command hierarchy ends when its owner leaves, and its members are told why: the ranks are
//! the owner's alone, so nobody else can hold the group, and the members may start a new one.
//! A flat group is handed on instead (see `group_owner_succession`).
//!
//! ```text
//! O and A befriend; O creates a command-hierarchy group inviting A; A joins
//! O leaves; A must be told the group ended because its hierarchy's owner is gone
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
    async fn a_hierarchy_ends_when_its_owner_leaves_and_its_members_are_told_why() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let (server, addr, _server_remote) = probed_server();
        let owner_name = format!("gho_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("ghm_{}", &Uuid::new_v4().to_string()[..8]);
        let joined = Arc::new(Barrier::new(2));
        let reason = Arc::new(Mutex::new(None));

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let joined = joined.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let options = MessageGroupOptions {
                        hierarchy: GroupHierarchyMode::CommandHierarchy {
                            read_policy: ReadPolicy::BroadcastAudit,
                            ranks: Default::default(),
                        },
                        ..Default::default()
                    };
                    let (conn, mut channel) =
                        open_group(&remote, addr, (&me, &peer), options).await?;
                    joined.wait().await;
                    assert!(leave(&mut channel).await?, "the owner's leave was refused");
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (joined, reason) = (joined.clone(), reason.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let (conn, mut channel) =
                        join_group(&remote, addr, (&me, &peer), &mut events).await?;
                    joined.wait().await;
                    *reason.lock().unwrap() = Some(disconnected(&mut channel).await);
                    assert_eq!(channel.owner(), None);
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        run_pair(server, client_node(owner), client_node(member)).await;
        assert_eq!(
            *reason.lock().unwrap(),
            Some(GroupEndReason::HierarchyOwnerGone),
            "the member was not told its hierarchy ended with its owner"
        );
    }
}
