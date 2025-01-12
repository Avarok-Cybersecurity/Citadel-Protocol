//! Testing Utilities for Citadel Protocol
//!
//! This module provides common utilities and helpers for testing Citadel Protocol
//! components. It includes functions for setting up test servers, managing test
//! barriers, and performing common assertions.
//!
//! # Features
//! - Test server creation and configuration
//! - Synchronization barriers for multi-peer tests
//! - UDP mode testing utilities
//! - P2P connection testing helpers
//! - Local test peer management
//!
//! # Example
//! ```rust
//! use citadel_sdk::test_common::*;
//! use citadel_sdk::prelude::*;
//!
//! async fn test_server() {
//!     // Create a test server with default settings
//!     let (server_future, addr) = server_info::<StackedRatchet>();
//!
//!     // Run server and handle connections
//!     server_future.await.expect("Server failed to start");
//! }
//! ```
//!
//! # Important Notes
//! - Most functionality requires "localhost-testing" feature
//! - Test barriers help coordinate multi-peer tests
//! - UDP assertions verify connection modes
//! - P2P assertions validate peer connections
//!
//! # Related Components
//! - [`DefaultNodeBuilder`]: Server configuration builder
//! - [`EmptyKernel`]: Basic test server kernel
//! - [`UdpMode`]: UDP connection configuration
//! - [`PeerConnectSuccess`]: Peer connection validation
//!

#![allow(missing_docs, unused_imports)]
#![doc(hidden)]
use crate::prefabs::server::client_connect_listener::ClientConnectListenerKernel;
use crate::prefabs::server::empty::EmptyKernel;
use crate::prefabs::ClientServerRemote;
use crate::prelude::results::PeerConnectSuccess;
use crate::prelude::*;
use citadel_io::tokio::net::TcpListener;
use futures::Future;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

#[allow(dead_code)]
pub fn server_test_node<'a, K: NetKernel<R> + 'a, R: Ratchet>(
    kernel: K,
    opts: impl FnOnce(&mut NodeBuilder<R>),
) -> (NodeFuture<'a, K>, SocketAddr) {
    let mut builder = NodeBuilder::default();
    let tcp_listener = citadel_wire::socket_helpers::get_tcp_listener("127.0.0.1:0")
        .expect("Failed to create TCP listener");
    let bind_addr = tcp_listener.local_addr().unwrap();
    let builder = builder
        .with_node_type(NodeType::Server(bind_addr))
        .with_underlying_protocol(
            ServerUnderlyingProtocol::from_tokio_tcp_listener(tcp_listener).unwrap(),
        );

    (opts)(builder);

    (builder.build::<K>(kernel).unwrap(), bind_addr)
}

#[allow(dead_code)]
#[cfg(feature = "localhost-testing")]
pub fn server_info<'a, R: Ratchet>() -> (NodeFuture<'a, EmptyKernel<R>>, SocketAddr) {
    crate::test_common::server_test_node(EmptyKernel::<R>::default(), |_| {})
}

#[allow(dead_code)]
#[cfg(not(feature = "localhost-testing"))]
pub fn server_info<'a, R: Ratchet>() -> (NodeFuture<'a, EmptyKernel<R>>, SocketAddr) {
    panic!("Function server_info is not available without the localhost-testing feature");
}

#[allow(dead_code)]
#[cfg(feature = "localhost-testing")]
pub fn server_info_reactive<'a, F, Fut, R: Ratchet>(
    f: F,
    opts: impl FnOnce(&mut NodeBuilder<R>),
) -> (NodeFuture<'a, Box<dyn NetKernel<R> + 'a>>, SocketAddr)
where
    F: Fn(CitadelClientServerConnection<R>) -> Fut + Send + Sync + 'a,
    Fut: Future<Output = Result<(), NetworkError>> + Send + Sync + 'a,
{
    server_test_node(
        Box::new(ClientConnectListenerKernel::<_, _, R>::new(f)) as Box<dyn NetKernel<R>>,
        opts,
    )
}

#[allow(dead_code)]
#[cfg(not(feature = "localhost-testing"))]
pub fn server_info_reactive<
    'a,
    F: Fn(CitadelClientServerConnection<R>) -> Fut + Send + Sync + 'a,
    Fut: Future<Output = Result<(), NetworkError>> + Send + Sync + 'a,
    R: Ratchet,
>(
    _f: F,
    _opts: impl FnOnce(&mut NodeBuilder<R>),
) -> (NodeFuture<'a, Box<dyn NetKernel<R> + 'a>>, SocketAddr) {
    panic!("Function server_info_reactive is not available without the localhost-testing feature");
}

#[cfg(feature = "localhost-testing")]
pub async fn wait_for_peers() {
    let barrier = { TEST_BARRIER.lock().clone() };
    assert!(*DEADLOCK_INIT, "Deadlock detector not initialized");
    if let Some(test_barrier) = barrier {
        // Wait for all peers to reach this point in the code
        test_barrier.wait().await;
    }
}

#[cfg(not(feature = "localhost-testing"))]
pub async fn wait_for_peers() {}

#[cfg(feature = "localhost-testing")]
pub fn num_local_test_peers() -> usize {
    let barrier = { TEST_BARRIER.lock().clone() };
    assert!(*DEADLOCK_INIT, "Deadlock detector not initialized");
    if let Some(test_barrier) = barrier {
        // Wait for all peers to reach this point in the code
        test_barrier.count
    } else {
        panic!("Test barrier should be initialized")
    }
}

#[cfg(not(feature = "localhost-testing"))]
pub const fn num_local_test_peers() -> usize {
    0
}

#[cfg(feature = "localhost-testing")]
pub static TEST_BARRIER: citadel_io::Mutex<Option<TestBarrier>> = citadel_io::const_mutex(None);

#[derive(Clone)]
#[allow(dead_code)]
pub struct TestBarrier {
    #[allow(dead_code)]
    pub inner: std::sync::Arc<citadel_io::tokio::sync::Barrier>,
    count: usize,
}

#[cfg(feature = "localhost-testing")]
impl TestBarrier {
    pub fn setup(count: usize) {
        assert!(TEST_BARRIER.lock().replace(Self::new(count)).is_none(), "TestBarrier already set up. Make sure to run tests in separate program spaces to ensure that the barrier is not shared across tests. E.g., run with `cargo nextest run` instead of `cargo test`");
    }
    #[allow(dead_code)]
    pub(crate) fn new(count: usize) -> Self {
        Self {
            inner: std::sync::Arc::new(citadel_io::tokio::sync::Barrier::new(count)),
            count,
        }
    }
    pub async fn wait(&self) {
        let _ = self.inner.wait().await;
    }
}

#[cfg(not(feature = "localhost-testing"))]
impl TestBarrier {
    pub fn setup(_count: usize) {
        panic!("TestBarrier is not available without the localhost-testing feature");
    }
    #[allow(dead_code)]
    pub(crate) fn new(_count: usize) -> Self {
        panic!("TestBarrier is not available without the localhost-testing feature");
    }
    pub async fn wait(&self) {
        panic!("TestBarrier is not available without the localhost-testing feature");
    }
}

#[cfg(feature = "localhost-testing")]
lazy_static::lazy_static! {
    static ref DEADLOCK_INIT: bool = {
        let _ = std::thread::spawn(move || {
            log::trace!(target: "citadel", "Executing deadlock detector ...");
            use std::thread;
            use std::time::Duration;
            use citadel_io::deadlock;
            loop {
                std::thread::sleep(Duration::from_secs(5));
                let deadlocks = deadlock::check_deadlock();
                if deadlocks.is_empty() {
                    log::trace!(target: "citadel", "No deadlocks detected");
                    continue;
                }

                log::error!(target: "citadel", "{} deadlocks detected", deadlocks.len());
                for (i, threads) in deadlocks.iter().enumerate() {
                    log::error!(target: "citadel", "Deadlock #{}", i);
                    for t in threads {
                        log::error!(target: "citadel", "Thread Id {:#?}", t.thread_id());
                        log::error!(target: "citadel", "{:#?}", t.backtrace());
                    }
                }
            }
        });

        true
    };
}

#[cfg_attr(
    feature = "localhost-testing",
    tracing::instrument(level = "trace", target = "citadel")
)]
#[allow(dead_code)]
pub async fn udp_mode_assertions<R: Ratchet>(
    udp_mode: UdpMode,
    udp_channel_rx_opt: Option<citadel_io::tokio::sync::oneshot::Receiver<UdpChannel<R>>>,
) {
    use futures::StreamExt;
    citadel_logging::info!(target: "citadel", "Inside UDP mode assertions ...");
    match udp_mode {
        UdpMode::Enabled => {
            // Wait to give time for the other side to finish connecting
            citadel_io::tokio::time::sleep(Duration::from_millis(500)).await;
            citadel_logging::info!(target: "citadel", "Inside UDP mode assertions AB1 ...");
            assert!(udp_channel_rx_opt.is_some());
            citadel_logging::info!(target: "citadel", "Inside UDP mode assertions AB1.5 ...");
            let chan = udp_channel_rx_opt.unwrap().await.unwrap();
            citadel_logging::info!(target: "citadel", "Inside UDP mode assertions AB2 ...");
            let (tx, mut rx) = chan.split();
            tx.unbounded_send(b"Hello, world!" as &[u8]).unwrap();
            assert_eq!(rx.next().await.unwrap().as_ref(), b"Hello, world!");
            citadel_logging::info!(target: "citadel", "Inside UDP mode assertions AB2.5 ...");
            tx.unbounded_send(b"Hello, world!" as &[u8]).unwrap();
            assert_eq!(rx.next().await.unwrap().as_ref(), b"Hello, world!");
            // wait to give time for the other side to receive the message
            citadel_io::tokio::time::sleep(Duration::from_millis(500)).await;
            //wait_for_peers().await;
            std::mem::forget((tx, rx)); // do not run destructor to not trigger premature
        }

        UdpMode::Disabled => {
            citadel_logging::info!(target: "citadel", "Inside UDP mode assertions AB0-null ...");
            assert!(udp_channel_rx_opt.is_none());
        }
    }

    log::info!(target: "citadel", "Done w/ UDP mode assertions");
}

#[cfg(feature = "localhost-testing")]
#[allow(dead_code)]
pub async fn p2p_assertions<R: Ratchet>(session_cid: u64, conn_success: &PeerConnectSuccess<R>) {
    log::info!(target: "citadel", "Inside p2p assertions ...");
    let peer_cid = conn_success.channel.get_peer_cid();

    assert_eq!(session_cid, conn_success.channel.get_session_cid());
    assert_ne!(session_cid, peer_cid);
    assert!(conn_success
        .remote
        .inner
        .account_manager()
        .get_persistence_handler()
        .hyperlan_peer_exists(session_cid, peer_cid)
        .await
        .unwrap());

    log::info!(target: "citadel", "Done w/ p2p mode assertions");
}

#[cfg(not(feature = "localhost-testing"))]
#[allow(dead_code)]
pub async fn p2p_assertions<R: Ratchet>(_session_cid: u64, _conn_success: &PeerConnectSuccess<R>) {}
