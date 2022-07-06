use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
use crate::hdp::state_subcontainers::preconnect_state_container::UdpChannelSender;
use hyxe_crypt::stacked_ratchet::constructor::StackedRatchetConstructor;

pub struct PeerKemStateContainer {
    pub(crate) constructor: Option<StackedRatchetConstructor>,
    pub(crate) local_is_initiator: bool,
    pub(crate) session_security_settings: SessionSecuritySettings,
    pub(crate) udp_channel_sender: UdpChannelSender,
}

impl PeerKemStateContainer {
    pub fn new(session_security_settings: SessionSecuritySettings, udp_enabled: bool) -> Self {
        Self {
            constructor: None,
            local_is_initiator: false,
            session_security_settings,
            udp_channel_sender: if udp_enabled {
                UdpChannelSender::default()
            } else {
                UdpChannelSender::empty()
            },
        }
    }
}
