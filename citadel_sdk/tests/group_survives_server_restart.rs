#![cfg(not(target_family = "wasm"))]
//! A group survives a restart of the SERVER, not only of its clients.
//!
//! The server's group registry (owner → groups, members, retention holds) lived only in memory.
//! A Durable Object reset or any server restart therefore destroyed every group silently: both
//! clients reconnected by themselves, the restore protocol had nothing to restore from, and group
//! messages reached nobody with no error at either end. The registry is now kept in the server's
//! account backend and loaded when the server starts.
//!
//! ```text
//! A (owner), B: register → connect → mutual peer register (server v1, filesystem backend)
//! A: create group inviting B → B accepts → A sends "before" → B receives it
//! server v1 shuts down; server v2 starts on the same address over the same backend directory
//! A, B: reconnect (credentials only; nothing group-related is called)
//! A and B must each get a group channel back; A sends "after-N" until B receives one;
//!   B sends "reply-N" until A receives one
//! ```

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::group::*;
    use citadel_io::tokio;
    use citadel_io::tokio::sync::{Barrier, Mutex};
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::wait_for_peers;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    type RemoteSlot = Arc<Mutex<Option<NodeRemote<StackedRatchet>>>>;

    /// A server kernel that does nothing but hand its remote out, so the test can shut it down.
    struct RemoteSlotKernel(RemoteSlot);

    #[async_trait]
    impl NetKernel<StackedRatchet> for RemoteSlotKernel {
        fn load_remote(&mut self, remote: NodeRemote<StackedRatchet>) -> Result<(), NetworkError> {
            *self.0.try_lock().expect("uncontended at load") = Some(remote);
            Ok(())
        }
        async fn on_start(&self) -> Result<(), NetworkError> {
            Ok(())
        }
        async fn on_node_event_received(
            &self,
            _message: NodeResult<StackedRatchet>,
        ) -> Result<(), NetworkError> {
            Ok(())
        }
        async fn on_stop(&mut self) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    fn server_node(
        listener: tokio::net::TcpListener,
        backend_dir: &std::path::Path,
        slot: RemoteSlot,
    ) -> NodeFuture<'static, RemoteSlotKernel> {
        let bind_addr = listener.local_addr().unwrap();
        let mut builder = DefaultNodeBuilder::default();
        let _ = builder
            .with_node_type(NodeType::Server(bind_addr))
            .with_underlying_protocol(ServerMode::OrderedReliable(
                NativeOrderedReliableConfig::from_tokio_listener(listener).unwrap(),
            ))
            .with_backend(BackendType::Filesystem(
                backend_dir.to_string_lossy().to_string(),
            ));
        builder.build(RemoteSlotKernel(slot)).unwrap()
    }

    /// The old server's accepted connections linger in TIME_WAIT on this port, so the restarted
    /// server binds with SO_REUSEADDR, as any server restarting in place must.
    fn rebind(addr: SocketAddr) -> tokio::net::TcpListener {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket
            .bind(addr)
            .unwrap_or_else(|err| panic!("could not rebind {addr} for server v2: {err}"));
        socket.listen(1024).unwrap()
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_group_survives_a_server_restart() {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);

        let backend_dir = std::env::temp_dir().join(format!("citadel-gsr-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&backend_dir).unwrap();
        let listener = citadel_wire::socket_helpers::get_tcp_listener("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        let owner_name = format!("gso_{}", &Uuid::new_v4().to_string()[..8]);
        let member_name = format!("gsm_{}", &Uuid::new_v4().to_string()[..8]);
        // Three parties: the two clients and the server orchestration below.
        let ready_for_restart = Arc::new(Barrier::new(3));
        let server_back = Arc::new(Barrier::new(3));
        let done = Arc::new(Barrier::new(2));
        let member_got_after = Arc::new(AtomicBool::new(false));
        let owner_got_reply = Arc::new(AtomicBool::new(false));

        let server = {
            let (ready_for_restart, server_back) = (ready_for_restart.clone(), server_back.clone());
            let backend_dir = backend_dir.clone();
            async move {
                let slot: RemoteSlot = Arc::new(Mutex::new(None));
                let v1 = server_node(listener, &backend_dir, slot.clone());
                tokio::pin!(v1);
                tokio::select! {
                    res = &mut v1 => return res.map(|_| ()),
                    _ = ready_for_restart.wait() => {}
                }
                let remote = slot
                    .lock()
                    .await
                    .take()
                    .expect("server v1 loaded its remote");
                remote.shutdown().await?;
                tokio::time::timeout(Duration::from_secs(10), &mut v1)
                    .await
                    .expect("server v1 did not stop")
                    .map_err(|err| NetworkError::msg(format!("server v1: {err:?}")))?;
                log::info!(target: "citadel", "server v1 stopped; starting v2 over the same backend");

                let v2 = server_node(
                    rebind(server_addr),
                    &backend_dir,
                    Arc::new(Mutex::new(None)),
                );
                tokio::pin!(v2);
                tokio::select! {
                    res = &mut v2 => return res.map(|_| ()),
                    _ = server_back.wait() => {}
                }
                v2.await.map(|_| ())
            }
        };

        let owner = {
            let (me, peer) = (owner_name.clone(), member_name.clone());
            let (ready_for_restart, server_back, done) =
                (ready_for_restart.clone(), server_back.clone(), done.clone());
            let (member_got_after, owner_got_reply) =
                (member_got_after.clone(), owner_got_reply.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let conn =
                        register_connect_and_befriend(&remote, server_addr, &me, &peer).await?;
                    let first_channel = conn.create_group(Some(vec![peer.clone().into()])).await?;
                    let key = first_channel.key();
                    wait_for_peers().await;
                    first_channel
                        .send_message(SecBuffer::from(b"before".to_vec()))
                        .await?;
                    ready_for_restart.wait().await;
                    server_back.wait().await;

                    session_ended(&mut events, "owner").await;
                    let conn = reconnect(&remote, &me).await?;
                    log::info!(target: "citadel", "[owner] reconnected to the restarted server");
                    drop(first_channel);

                    // Nothing group-related is called from here on.
                    let mut channel = next_group_channel(&mut events, "owner").await;
                    assert_eq!(channel.key(), key, "the owner gets the same group back");
                    send_until(&channel, "after", &member_got_after).await?;
                    let reply = next_message_with_prefix(&mut channel, "reply-").await;
                    log::info!(target: "citadel", "[owner] received {:?} after the server restart", String::from_utf8_lossy(&reply));
                    owner_got_reply.store(true, Ordering::SeqCst);
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let member = {
            let (me, peer) = (member_name.clone(), owner_name.clone());
            let (ready_for_restart, server_back, done) =
                (ready_for_restart.clone(), server_back.clone(), done.clone());
            let (member_got_after, owner_got_reply) =
                (member_got_after.clone(), owner_got_reply.clone());
            GroupTestKernel::new(
                move |remote: NodeRemote<StackedRatchet>, mut events: Events| async move {
                    let conn =
                        register_connect_and_befriend(&remote, server_addr, &me, &peer).await?;
                    let invitation = next_invitation(&mut events).await;
                    let _ = responses::group_invite(invitation, true, &remote).await?;
                    let mut first_channel = next_group_channel(&mut events, "member").await;
                    wait_for_peers().await;
                    assert_eq!(
                        next_message_with_prefix(&mut first_channel, "before").await,
                        b"before"
                    );
                    let cid = conn.cid;
                    ready_for_restart.wait().await;
                    server_back.wait().await;

                    session_ended(&mut events, "member").await;
                    let conn = reconnect(&remote, &me).await?;
                    log::info!(target: "citadel", "[member] reconnected to the restarted server");
                    assert_eq!(conn.cid, cid, "CID is permanent per account");
                    drop(first_channel);

                    let mut channel = next_group_channel(&mut events, "member").await;
                    let after = next_message_with_prefix(&mut channel, "after-").await;
                    log::info!(target: "citadel", "[member] received {:?} after the server restart", String::from_utf8_lossy(&after));
                    member_got_after.store(true, Ordering::SeqCst);
                    send_until(&channel, "reply", &owner_got_reply).await?;
                    done.wait().await;
                    drop(channel);
                    conn.shutdown_kernel().await
                },
            )
        };

        let owner = DefaultNodeBuilder::default().build(owner).unwrap();
        let member = DefaultNodeBuilder::default().build(member).unwrap();
        run_pair(server, owner, member).await;
        let _ = std::fs::remove_dir_all(&backend_dir);
        assert!(member_got_after.load(Ordering::SeqCst));
        assert!(owner_got_reply.load(Ordering::SeqCst));
    }
}
