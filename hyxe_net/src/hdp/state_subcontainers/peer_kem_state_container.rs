use ez_pqcrypto::PostQuantumContainer;
use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
use crate::hdp::peer::channel::PeerChannel;

pub struct PeerKemStateContainer {
    pub(crate) last_state: u8,
    // when alice creates her initial pqc, she won't have generated a shared key. We thus can't wrap the pqc
    // inside a Rc quite yet ...
    pub(crate) pqc: Option<PostQuantumContainer>,
    pub(crate) nonce: Option<[u8; AES_GCM_NONCE_LEN_BYTES]>,
    pub(crate) channel: Option<PeerChannel>
}

impl Default for PeerKemStateContainer {
    fn default() -> Self {
        Self { channel: None, nonce: None, last_state: 0, pqc: None }
    }
}