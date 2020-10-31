use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;

use crate::constants::DO_DEREGISTER_EXPIRE_TIME_NS;
use crate::hdp::hdp_server::Ticket;
use crate::hdp::state_container::VirtualConnectionType;

/// For keeping track of deregistration processes
pub struct DeRegisterState {
    pub(crate) last_stage: u8,
    pub(crate) nonce: Option<[u8; AES_GCM_NONCE_LEN_BYTES]>,
    pub(crate) last_packet_time: Option<i64>,
    pub(crate) in_progress: bool,
    pub(crate) current_ticket: Option<Ticket>,
    pub(crate) virtual_connection_type: Option<VirtualConnectionType>
}

impl DeRegisterState {
    /// run this when it begins
    pub fn on_init(&mut self, virtual_connection_type: VirtualConnectionType, timestamp: i64, ticket: Ticket) {
        self.in_progress = true;
        self.last_packet_time = Some(timestamp);
        self.current_ticket = Some(ticket);
        self.virtual_connection_type = Some(virtual_connection_type);
    }
    /// Whenever a *valid* DO_DRILL_UPDATE packet is received, call this
    pub fn on_packet_received(&mut self, timestamp: i64) {
        self.last_packet_time = Some(timestamp);
    }

    /// Run this on success
    pub fn on_success(&mut self) {
        self.last_stage = 0;
        self.nonce = None;
        self.last_packet_time = None;
        self.current_ticket = None;
        self.virtual_connection_type = None;
    }

    /// run this on fail
    pub fn on_fail(&mut self) {
        self.on_success();
    }

    /// This should be periodically polled. If this returns true, the entire session should end for security purposes
    pub fn has_expired(&self, current_time: i64) -> bool {
        if self.in_progress {
            let last_packet_stamp = self.last_packet_time.as_ref().unwrap();
            if current_time - *last_packet_stamp > DO_DEREGISTER_EXPIRE_TIME_NS {
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl Default for DeRegisterState {
    fn default() -> Self {
        Self { last_stage: 0, nonce: None, last_packet_time: None, in_progress: false, current_ticket: None, virtual_connection_type: None }
    }
}