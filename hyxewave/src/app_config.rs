use hyxe_net::hdp::hdp_packet_processor::includes::{IpAddr, SocketAddr};
use hyxe_net::re_imports::HyperNodeType;
use crate::ffi::FFIIO;

/// Created when parsing the command-line. If pure server or client mode is chosen,
/// only one of the fields below will contain a value. If distributed mode is used,
/// both will contain a value
pub struct AppConfig {
    pub bind_addr: Option<IpAddr>,
    pub pipe: Option<SocketAddr>,
    pub hypernode_type: Option<HyperNodeType>,
    pub ffi_io: Option<FFIIO>,
    pub is_ffi: bool,
    pub home_dir: Option<String>,
    pub daemon_mode: bool
}

impl Default for AppConfig {
    fn default() -> Self {
        Self { daemon_mode: false, home_dir: None, is_ffi: false, ffi_io: None, bind_addr: None, pipe: None, hypernode_type: None }
    }
}