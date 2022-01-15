#![allow(missing_docs)]

use crate::prelude::*;
use std::net::SocketAddr;
use crate::prefabs::server::empty_kernel::EmptyKernel;

pub fn setup_log() {
    std::env::set_var("RUST_LOG", "error,warn,info,trace");
    //std::env::set_var("RUST_LOG", "error");
    let _ = env_logger::try_init();
    log::trace!("TRACE enabled");
    log::info!("INFO enabled");
    log::warn!("WARN enabled");
    log::error!("ERROR enabled");
}

pub fn default_server_test_node(bind_addr: SocketAddr) -> NodeFuture {
    NodeBuilder::default()
        .with_node_type(NodeType::Server(bind_addr))
        .build(EmptyKernel::default()).unwrap()
}