#![allow(missing_docs, unused_imports)]
use crate::prelude::*;
use std::net::SocketAddr;
use crate::prefabs::server::empty::EmptyKernel;
use futures::Future;
use crate::prefabs::ClientServerRemote;
use std::str::FromStr;
use crate::prefabs::server::client_connect_listener::ClientConnectListenerKernel;

#[allow(dead_code)]
pub fn setup_log() {
    std::env::set_var("RUST_LOG", "error,warn,info,trace");
    let _ = env_logger::try_init();
    log::trace!("TRACE enabled");
    log::info!("INFO enabled");
    log::warn!("WARN enabled");
    log::error!("ERROR enabled");
}

#[allow(dead_code)]
pub fn server_test_node<K: NetKernel>(bind_addr: SocketAddr, kernel: K) -> NodeFuture<K> {
    NodeBuilder::default()
        .with_node_type(NodeType::Server(bind_addr))
        .build(kernel).unwrap()
}

#[allow(dead_code)]
#[cfg(test)]
pub fn server_info() -> (NodeFuture<EmptyKernel>, SocketAddr) {
    let port = portpicker::pick_unused_port().unwrap();
    let bind_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap();
    let server = crate::test_common::server_test_node(bind_addr, EmptyKernel::default());
    (server, bind_addr)
}

#[cfg(test)]
lazy_static::lazy_static! {
    pub static ref PEERS: Vec<(String, String, String)> = {
        ["alpha", "beta", "charlie", "echo", "delta", "epsilon", "foxtrot"]
        .iter().map(|base| (format!("{}.username", base), format!("{}.password", base), format!("{}.full_name", base)))
        .collect()
    };
}