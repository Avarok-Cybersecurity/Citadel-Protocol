use ez_pqcrypto::PostQuantumContainer;
use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
use crate::hdp::peer::channel::PeerChannel;
use crate::hdp::hdp_packet_processor::includes::SocketAddr;

#[derive(Default)]
pub struct PeerKemStateContainer {
    pub(crate) last_state: u8,
    // when alice creates her initial pqc, she won't have generated a shared key. We thus can't wrap the pqc
    // inside a Rc quite yet ...
    pub(crate) pqc: Option<PostQuantumContainer>,
    pub(crate) nonce: Option<[u8; AES_GCM_NONCE_LEN_BYTES]>,
    pub(crate) channel: Option<PeerChannel>,
    // during the NAT-traversal sage, this gets flipped ON if the local node makes it across
    pub(crate) p2p_conn_established: bool,
    pub(crate) local_is_initiator: bool,
    pub(crate) verified_socket_addr: Option<SocketAddr>
}