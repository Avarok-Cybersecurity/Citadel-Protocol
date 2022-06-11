#![allow(missing_docs, unused_imports)]
#![doc(hidden)]
use crate::prelude::*;
use std::net::SocketAddr;
use crate::prefabs::server::empty::EmptyKernel;
use futures::Future;
use crate::prefabs::ClientServerRemote;
use std::str::FromStr;
use crate::prefabs::server::client_connect_listener::ClientConnectListenerKernel;
use tokio::net::TcpListener;

#[allow(dead_code)]
pub fn setup_log() {
    let _ = env_logger::try_init();
    log::trace!(target: "lusna", "TRACE enabled");
    log::trace!(target: "lusna", "INFO enabled");
    log::warn!(target: "lusna", "WARN enabled");
    log::error!(target: "lusna", "ERROR enabled");
}

#[allow(dead_code)]
pub fn server_test_node<'a, K: NetKernel + 'a>(bind_addr: SocketAddr, kernel: K) -> NodeFuture<'a, K> {
    NodeBuilder::default()
        .with_node_type(NodeType::Server(bind_addr))
        .build(kernel).unwrap()
}

#[allow(dead_code)]
#[cfg(feature = "localhost-testing")]
pub fn server_info<'a>() -> (NodeFuture<'a, EmptyKernel>, SocketAddr) {
    let port = get_unused_tcp_port();
    let bind_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap();
    let server = crate::test_common::server_test_node(bind_addr, EmptyKernel::default());
    (server, bind_addr)
}

#[cfg(feature = "localhost-testing")]
pub fn get_unused_tcp_port() -> u16 {
    std::net::TcpListener::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port()
}

#[cfg(feature = "localhost-testing")]
lazy_static::lazy_static! {
    pub static ref PEERS: Vec<(String, String, String)> = {
        ["alpha", "beta", "charlie", "echo", "delta", "epsilon", "foxtrot"]
        .iter().map(|base| (format!("{}.username", base), format!("{}.password", base), format!("{}.full_name", base)))
        .collect()
    };
}

#[cfg(feature = "localhost-testing")]
pub async fn wait_for_peers() {
    let barrier = {
        TEST_BARRIER.lock().clone()
    };

    if let Some(test_barrier) = barrier {
        // wait for all peers to reach this point in the code
        test_barrier.wait().await;
    }
}

#[cfg(not(feature = "localhost-testing"))]
pub async fn wait_for_peers() {}

#[cfg(feature = "localhost-testing")]
pub static TEST_BARRIER: parking_lot::Mutex<Option<TestBarrier>> = parking_lot::const_mutex(None);

#[derive(Clone)]
pub struct TestBarrier {
    #[allow(dead_code)]
    pub inner: std::sync::Arc<tokio::sync::Barrier>
}

#[cfg(feature = "localhost-testing")]
impl TestBarrier {
    pub fn setup(count: usize) {
        let _ = TEST_BARRIER.lock().replace(Self::new(count));
    }
    fn new(count: usize) -> Self {
        Self { inner: std::sync::Arc::new(tokio::sync::Barrier::new(count)) }
    }
    pub async fn wait(&self) {
        let _ = self.inner.wait().await;
    }
}