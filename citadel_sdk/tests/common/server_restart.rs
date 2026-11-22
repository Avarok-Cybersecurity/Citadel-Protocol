//! A server that restarts in place: v1 serves until the clients are ready, stops, and v2 starts
//! on the same address over the same backend directory.

use citadel_io::tokio;
use citadel_io::tokio::sync::{Barrier, Mutex};
use citadel_sdk::prelude::*;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub type RemoteSlot = Arc<Mutex<Option<NodeRemote<StackedRatchet>>>>;

/// A server kernel that does nothing but hand its remote out, so the test can shut it down.
pub struct RemoteSlotKernel(pub RemoteSlot);

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

pub fn server_node(
    listener: tokio::net::TcpListener,
    backend_dir: &std::path::Path,
    slot: RemoteSlot,
) -> NodeFuture<'static, RemoteSlotKernel> {
    let bind_addr = listener.local_addr().unwrap();
    let mut builder = citadel_sdk::test_common::node_builder();
    let _ = builder.with_link_manager(LinkManagerMode::Legacy);
    let _ = builder
        .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
        .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level());
    let _ = builder
        .with_node_type(NodeType::Server(bind_addr))
        .with_path_policy(citadel_sdk::test_common::localhost_path_policy())
        .with_server_limits(citadel_sdk::test_common::localhost_server_limits())
        .with_group_mail_limits(citadel_sdk::test_common::localhost_group_mail_limits())
        .with_underlying_protocol(ServerMode::OrderedReliable(
            NativeOrderedReliableConfig::from_tokio_listener(listener).unwrap(),
        ))
        .with_backend(BackendType::Filesystem(
            backend_dir.to_string_lossy().to_string(),
        ));
    builder.build(RemoteSlotKernel(slot)).unwrap()
}

/// A listener with SO_REUSEADDR, for BOTH servers. On Linux a socket may bind a port others
/// hold only if every socket there set SO_REUSEADDR -- and the old server's accepted client
/// sockets inherit its listener's options. v1 was made with `get_tcp_listener` (no reuse), so
/// its live and TIME_WAIT connections kept v2 out ("Address already in use (os error 98)",
/// CI on PR #318) however long v2 waited. A server that restarts in place must reuse from its
/// first bind, as any real one does.
pub fn listener_at(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

/// v2 on v1's address. Retried, bounded, only on AddrInUse: v1's listening socket goes away
/// with its task, asynchronously.
pub fn rebind(addr: SocketAddr) -> tokio::net::TcpListener {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match listener_at(addr) {
            Ok(listener) => return listener,
            Err(err)
                if err.kind() == std::io::ErrorKind::AddrInUse
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(err) => panic!("could not rebind {addr} for server v2: {err}"),
        }
    }
}

/// Serves v1 on `listener` until `ready_for_restart` is passed, stops it, then serves v2 on the
/// same address over `backend_dir`, joining `server_back` once it is up.
pub async fn restarting_server(
    listener: tokio::net::TcpListener,
    backend_dir: PathBuf,
    ready_for_restart: Arc<Barrier>,
    server_back: Arc<Barrier>,
) -> Result<(), NetworkError> {
    let server_addr = listener.local_addr().unwrap();
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
