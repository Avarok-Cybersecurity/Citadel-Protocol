use rand::prelude::ThreadRng;
use rand::RngCore;

use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;

use crate::hdp::hdp_server::Ticket;
use crate::hdp::state_container::VirtualConnectionType;

/// Structure for processing a disconnect safely
pub struct DisconnectState {
    pub(crate) last_stage: u8,
    pub(crate) nonce: Option<[u8; AES_GCM_NONCE_LEN_BYTES]>,
    pub(crate) virtual_connection_type: Option<VirtualConnectionType>,
    pub(crate) ticket: Ticket,
}

impl DisconnectState {

    pub fn reset(&mut self) {
        self.last_stage = 0;
        self.nonce = None;
        self.virtual_connection_type = None;
        self.ticket = Ticket(0);
    }

}

impl Default for DisconnectState {
    /// Sets the ticket to a random value, to instantly deny a packet that may be spoofed in a later stage
    fn default() -> Self {
        Self { virtual_connection_type: None, last_stage: 0, nonce: None, ticket: ThreadRng::default().next_u64().into() }
    }
}