#![cfg(not(target_family = "wasm"))]
//! A group created, accepted and messaged both ways against a server reached by WebSocket URL.
//!
//! Run against any server, including the wasm32 build a Durable Object hosts:
//!
//! ```text
//! CITADEL_GROUP_ENDPOINT=ws://127.0.0.1:8807/acme \
//!   cargo test -p citadel_sdk --features localhost-testing \
//!   --test group_round_trip_over_endpoint -- --ignored
//! ```
//!
//! Without the variable it runs against a native server with a WebSocket listener.
//!
//! ```text
//! A, B: register to the URL → connect → mutual peer register
//! A: create group inviting B → B accepts → both channels open
//! A sends "hello-N" until B receives one; B sends "reply-N" until A receives one
//! A creates a second group inviting B → B accepts → B's second channel opens
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_io::WebSocketEndpoint;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::server_test_node_with_websocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

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

    async fn run(endpoint: WebSocketEndpoint) {
        let owner_name = format!("gwo_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gwm_{}", &Uuid::new_v4().to_string()[..8]);
        let sync = Arc::new(Barrier::new(2));
        let member_got_hello = Arc::new(AtomicBool::new(false));
        let owner_got_reply = Arc::new(AtomicBool::new(false));

        let owner = {
            let (me, peer, endpoint, sync) = (
                owner_name.clone(),
                member_name.clone(),
                endpoint.clone(),
                sync.clone(),
            );
            let (member_got_hello, owner_got_reply) =
                (member_got_hello.clone(), owner_got_reply.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, _events: Events| async move {
                    let conn = befriend(&remote, endpoint, &me, &peer, &sync).await?;
                    let mut channel = conn.create_group(Some(vec![peer.clone().into()])).await?;
                    send_until(&channel, "hello", &member_got_hello).await?;
                    assert!(
                        member_got_hello.load(Ordering::SeqCst),
                        "the member never read the owner's message"
                    );
                    let _ = next_message_with_prefix(&mut channel, "reply-").await;
                    owner_got_reply.store(true, Ordering::SeqCst);
                    sync.wait().await;

                    let second = conn.create_group(Some(vec![peer.clone().into()])).await?;
                    sync.wait().await;
                    drop((channel, second));
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer, endpoint, sync) = (
                member_name.clone(),
                owner_name.clone(),
                endpoint.clone(),
                sync.clone(),
            );
            let (member_got_hello, owner_got_reply) =
                (member_got_hello.clone(), owner_got_reply.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let conn = befriend(&remote, endpoint, &me, &peer, &sync).await?;
                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut channel = next_group_channel(&mut events, "member").await;
                    let _ = next_message_with_prefix(&mut channel, "hello-").await;
                    member_got_hello.store(true, Ordering::SeqCst);
                    send_until(&channel, "reply", &owner_got_reply).await?;
                    sync.wait().await;

                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let second = next_group_channel(&mut events, "member (second group)").await;
                    assert_ne!(second.key(), channel.key(), "a second, distinct group");
                    sync.wait().await;
                    drop((channel, second));
                    conn.shutdown_kernel().await
                },
            )
        };

        let owner = DefaultNodeBuilder::default().build(owner).unwrap();
        let member = DefaultNodeBuilder::default().build(member).unwrap();
        let clients = async move { futures::future::try_join(owner, member).await };
        let result = tokio::time::timeout(std::time::Duration::from_secs(150), clients)
            .await
            .expect("test timed out");
        if let Err(err) = result {
            panic!("test failed: {err:?}");
        }
        assert!(member_got_hello.load(Ordering::SeqCst));
        assert!(owner_got_reply.load(Ordering::SeqCst));
    }

    /// Against a native server with a WebSocket listener.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_group_round_trips_over_a_websocket_url() {
        citadel_logging::setup_log();
        let ((server, _tcp), ws_addr) =
            server_test_node_with_websocket(EmptyKernel::<StackedRatchet>::default(), |b| {
                let _ = b.with_backend(BackendType::InMemory);
            });
        let endpoint =
            WebSocketEndpoint::parse(&format!("ws://127.0.0.1:{}/acme", ws_addr.port())).unwrap();
        tokio::select! {
            res = server => panic!("server ended prematurely: {:?}", res.map(|_| ())),
            _ = run(endpoint) => {}
        }
    }

    /// Against the server at `CITADEL_GROUP_ENDPOINT` (e.g. the tenant Durable Object under
    /// `wrangler dev`, which runs the wasm32 server).
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    #[ignore = "needs CITADEL_GROUP_ENDPOINT: a running server's WebSocket URL"]
    async fn a_group_round_trips_against_an_external_server() {
        citadel_logging::setup_log();
        let url = std::env::var("CITADEL_GROUP_ENDPOINT")
            .expect("CITADEL_GROUP_ENDPOINT names the server's WebSocket URL");
        run(WebSocketEndpoint::parse(&url).expect("a ws:// or wss:// URL")).await;
    }
}
