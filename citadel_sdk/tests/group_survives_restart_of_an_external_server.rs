#![cfg(not(target_family = "wasm"))]
//! A group survives a restart of an external server, such as the wasm32 server a Durable Object
//! hosts: the same scenario as `group_survives_server_restart`, against a server this test does
//! not run. `CITADEL_SERVER_RESTART_CMD` must restart that server (keeping its storage) and return
//! once it is serving again.
//!
//! ```text
//! CITADEL_GROUP_ENDPOINT=ws://127.0.0.1:8847/acme \
//! CITADEL_SERVER_RESTART_CMD='kill -USR1 <supervisor>; wait-for-restart' \
//!   cargo test -p citadel_sdk --features localhost-testing \
//!   --test group_survives_restart_of_an_external_server -- --ignored
//! ```
//!
//! ```text
//! A, B: register to the URL → connect → mutual peer register
//! A: create group inviting B → "hello-N" until B reads one → B "reply-N" until A reads one
//! the server is restarted; A, B reconnect with credentials only
//! A and B must each get a group channel back; "after-N" A → B, then "back-N" B → A
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_io::WebSocketEndpoint;
    use citadel_sdk::prelude::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    struct Flags {
        member_got_hello: AtomicBool,
        owner_got_reply: AtomicBool,
        member_got_after: AtomicBool,
        owner_got_back: AtomicBool,
    }

    async fn befriend(
        remote: &NodeRemote<StackedRatchet>,
        endpoint: WebSocketEndpoint,
        me: &str,
        peer: &str,
        sync: &Barrier,
    ) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
        let reg = remote
            .register_to_endpoint(endpoint, me, me, PASSWORD, Default::default(), None)
            .await?;
        let conn = connect(remote, me).await?;
        sync.wait().await;
        let status = conn
            .propose_target(reg.cid, peer.to_string())
            .await?
            .register_to_peer()
            .await?;
        assert!(status.is_accepted(), "{me}: peer registration refused");
        sync.wait().await;
        Ok(conn)
    }

    fn restart_server(command: &str) {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .status()
            .expect("CITADEL_SERVER_RESTART_CMD could not be run");
        assert!(status.success(), "restarting the server failed: {status}");
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    #[ignore = "needs CITADEL_GROUP_ENDPOINT and CITADEL_SERVER_RESTART_CMD"]
    async fn a_group_survives_a_restart_of_an_external_server() {
        citadel_logging::setup_log();
        let url = std::env::var("CITADEL_GROUP_ENDPOINT").expect("CITADEL_GROUP_ENDPOINT");
        let restart =
            std::env::var("CITADEL_SERVER_RESTART_CMD").expect("CITADEL_SERVER_RESTART_CMD");
        let endpoint = WebSocketEndpoint::parse(&url).expect("a ws:// or wss:// URL");
        let owner_name = format!("gxo_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gxm_{}", &Uuid::new_v4().to_string()[..8]);
        let sync = Arc::new(Barrier::new(2));
        // The two clients and the restart below. The clients do not wait for the server to be
        // back: like an agent, they retry from the moment their sessions end, so attempts land on
        // a server that is still going down or still coming up.
        let ready_for_restart = Arc::new(Barrier::new(3));
        let flags = Arc::new(Flags {
            member_got_hello: AtomicBool::new(false),
            owner_got_reply: AtomicBool::new(false),
            member_got_after: AtomicBool::new(false),
            owner_got_back: AtomicBool::new(false),
        });

        let owner = {
            let (me, peer, endpoint, sync, flags) = (
                owner_name.clone(),
                member_name.clone(),
                endpoint.clone(),
                sync.clone(),
                flags.clone(),
            );
            let ready_for_restart = ready_for_restart.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let conn = befriend(&remote, endpoint, &me, &peer, &sync).await?;
                    let mut first = conn.create_group(Some(vec![peer.clone().into()])).await?;
                    let key = first.key();
                    send_until(&first, "hello", &flags.member_got_hello).await?;
                    let _ = next_message_with_prefix(&mut first, "reply-").await;
                    flags.owner_got_reply.store(true, Ordering::SeqCst);
                    ready_for_restart.wait().await;

                    session_ended(&mut events, "owner").await;
                    let conn = reconnect(&remote, &me).await?;
                    drop(first);
                    let mut channel = next_group_channel(&mut events, "owner").await;
                    assert_eq!(channel.key(), key, "the owner gets the same group back");
                    send_until(&channel, "after", &flags.member_got_after).await?;
                    let _ = next_message_with_prefix(&mut channel, "back-").await;
                    flags.owner_got_back.store(true, Ordering::SeqCst);
                    sync.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer, endpoint, sync, flags) = (
                member_name.clone(),
                owner_name.clone(),
                endpoint.clone(),
                sync.clone(),
                flags.clone(),
            );
            let ready_for_restart = ready_for_restart.clone();
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let _first_conn = befriend(&remote, endpoint, &me, &peer, &sync).await?;
                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut first = next_group_channel(&mut events, "member").await;
                    let _ = next_message_with_prefix(&mut first, "hello-").await;
                    flags.member_got_hello.store(true, Ordering::SeqCst);
                    send_until(&first, "reply", &flags.owner_got_reply).await?;
                    ready_for_restart.wait().await;

                    session_ended(&mut events, "member").await;
                    let conn = reconnect(&remote, &me).await?;
                    drop(first);
                    let mut channel = next_group_channel(&mut events, "member").await;
                    let _ = next_message_with_prefix(&mut channel, "after-").await;
                    flags.member_got_after.store(true, Ordering::SeqCst);
                    send_until(&channel, "back", &flags.owner_got_back).await?;
                    sync.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let restarter = async move {
            ready_for_restart.wait().await;
            tokio::task::spawn_blocking(move || restart_server(&restart))
                .await
                .expect("the restart task panicked");
            log::info!(target: "citadel", "the external server was restarted");
            Ok::<_, NetworkError>(())
        };

        let owner = DefaultNodeBuilder::default().build(owner).unwrap();
        let member = DefaultNodeBuilder::default().build(member).unwrap();
        let all = async move {
            futures::future::try_join3(owner, member, restarter)
                .await
                .map(|_| ())
        };
        let result = tokio::time::timeout(std::time::Duration::from_secs(240), all)
            .await
            .expect("test timed out");
        assert!(result.is_ok(), "test failed: {result:?}");
        assert!(flags.member_got_after.load(Ordering::SeqCst));
        assert!(flags.owner_got_back.load(Ordering::SeqCst));
    }
}
