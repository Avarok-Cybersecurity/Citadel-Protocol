use crate::hdp::hdp_packet_processor::includes::SocketAddr;
use hyxe_crypt::hyper_ratchet::constructor::HyperRatchetConstructor;

#[derive(Default)]
pub struct PeerKemStateContainer {
    pub(crate) last_state: u8,
    // when alice creates her initial pqc, she won't have generated a shared key. We thus can't wrap the pqc
    // inside a Rc quite yet ...
    pub(crate) constructor: Option<HyperRatchetConstructor>,
    // during the NAT-traversal sage, this gets flipped ON if the local node makes it across
    pub(crate) p2p_conn_established: bool,
    pub(crate) local_is_initiator: bool,
    pub(crate) verified_socket_addr: Option<SocketAddr>
}