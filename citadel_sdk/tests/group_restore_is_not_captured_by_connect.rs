#![cfg(not(target_family = "wasm"))]
//! The group channel a reconnect restores reaches the application's event
//! stream, not the connect request's listener.
//!
//! The server prompts a reconnecting node to restore its groups, and the node
//! opens the restored channel on the prompt's ticket. That ticket was the
//! CONNECT request's, so the channel was delivered to the connect listener,
//! which is still registered after it has read its result and discards
//! everything else when it is dropped. Whether the channel was lost depended on
//! how soon the caller dropped it: 1 in 10 runs of
//! `group_survives_server_restart`.
//!
//! Here the connect listener is held for the whole wait, which makes the loss
//! certain instead of occasional.
//!
//! ```text
//! A (owner), B: register → connect → mutual peer register
//! A: create group inviting B → B accepts → A sends "before" → B receives it
//! X (A in one test, B in the other): disconnect → connect, keeping the connect listener open
//! X must receive its group channel on the event stream
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers};
    use futures::StreamExt;
    use std::sync::Arc;
    use uuid::Uuid;

    #[derive(Clone, Copy, PartialEq)]
    enum Reconnecting {
        Owner,
        Member,
    }

    /// Connects with the defaults `connect_with_defaults` uses, and returns the
    /// connect request's listener after reading its success, still registered.
    async fn connect_keeping_the_listener(
        remote: &NodeRemote<StackedRatchet>,
        username: &str,
    ) -> Result<impl Send, NetworkError> {
        let mut listener = remote
            .send_callback_subscription(NodeRequest::ConnectToHypernode(ConnectToHypernode {
                auth_request: AuthenticationRequest::credentialed(username.to_string(), PASSWORD),
                connect_mode: ConnectMode::Standard { force_login: false },
                udp_mode: Default::default(),
                keep_alive_timeout: None,
                session_security_settings: Default::default(),
                session_password: Default::default(),
            }))
            .await?;
        match listener.next().await {
            Some(NodeResult::ConnectSuccess(_)) => Ok(listener),
            other => Err(NetworkError::msg(format!("reconnect failed: {other:?}"))),
        }
    }

    async fn restored_channel_reaches_the_event_stream(who: Reconnecting) {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        let (server, server_addr) = server_info::<StackedRatchet>();
        let owner_name = format!("gco_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gcm_{}", &Uuid::new_v4().to_string()[..8]);
        let received_before = Arc::new(Barrier::new(2));
        let done = Arc::new(Barrier::new(2));

        // Both roles run the same body; only `who` reconnects.
        let node = |me: String, peer: String, is_owner: bool| {
            let (received_before, done) = (received_before.clone(), done.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let conn =
                        register_connect_and_befriend(&remote, server_addr, &me, &peer).await?;
                    let channel = if is_owner {
                        let channel = conn.create_group(Some(vec![peer.clone().into()])).await?;
                        wait_for_peers().await;
                        channel
                            .send_message(SecBuffer::from(b"before".to_vec()))
                            .await?;
                        channel
                    } else {
                        let invitation = next_invitation(&mut events).await;
                        let _ = responses::group_invite(invitation, true, &remote).await?;
                        let mut channel = next_group_channel(&mut events, "member").await;
                        wait_for_peers().await;
                        let _ = next_message_with_prefix(&mut channel, "before").await;
                        channel
                    };
                    received_before.wait().await;

                    let role = if is_owner {
                        Reconnecting::Owner
                    } else {
                        Reconnecting::Member
                    };
                    if role == who {
                        // Not dropped first: that is an explicit LeaveRoom, not a lost session.
                        conn.disconnect().await?;
                        let connect_listener = connect_keeping_the_listener(&remote, &me).await?;
                        drop(channel);
                        let restored = next_group_channel(&mut events, &me).await;
                        drop((restored, connect_listener));
                        done.wait().await;
                    } else {
                        // Kept open: dropping it would leave the group.
                        done.wait().await;
                        drop(channel);
                    }
                    remote.shutdown().await
                },
            )
        };

        let owner = node(owner_name.clone(), member_name.clone(), true);
        let member = node(member_name, owner_name, false);
        let owner = DefaultNodeBuilder::default().build(owner).unwrap();
        let member = DefaultNodeBuilder::default().build(member).unwrap();
        run_pair(server, owner, member).await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn an_owners_restored_group_is_not_captured_by_its_connect() {
        restored_channel_reaches_the_event_stream(Reconnecting::Owner).await;
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_members_restored_group_is_not_captured_by_its_connect() {
        restored_channel_reaches_the_event_stream(Reconnecting::Member).await;
    }
}
