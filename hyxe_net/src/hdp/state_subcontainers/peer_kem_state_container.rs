use crate::hdp::hdp_packet_processor::includes::SocketAddr;
use hyxe_crypt::hyper_ratchet::constructor::HyperRatchetConstructor;
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;

pub struct PeerKemStateContainer {
    pub(crate) constructor: Option<HyperRatchetConstructor>,
    // during the NAT-traversal sage, this gets flipped ON if the local node makes it across
    pub(crate) p2p_conn_established: bool,
    pub(crate) local_is_initiator: bool,
    pub(crate) verified_socket_addr: Option<SocketAddr>,
    pub(crate) session_security_settings: SessionSecuritySettings
}

impl PeerKemStateContainer {
    pub fn new(session_security_settings: SessionSecuritySettings) -> Self {
        Self {
            constructor: None,
            p2p_conn_established: false,
            local_is_initiator: false,
            verified_socket_addr: None,
            session_security_settings
        }
    }
}