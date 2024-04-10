use crate::prelude::PreSharedKey;
use crate::proto::state_subcontainers::preconnect_state_container::UdpChannelSender;
use citadel_crypt::stacked_ratchet::constructor::StackedRatchetConstructor;
use citadel_types::proto::SessionSecuritySettings;

pub struct PeerKemStateContainer {
    pub(crate) constructor: Option<StackedRatchetConstructor>,
    pub(crate) local_is_initiator: bool,
    pub(crate) session_security_settings: SessionSecuritySettings,
    pub(crate) udp_channel_sender: UdpChannelSender,
    pub(crate) session_password: PreSharedKey,
}

impl PeerKemStateContainer {
    pub fn new(
        session_security_settings: SessionSecuritySettings,
        udp_enabled: bool,
        session_password: PreSharedKey,
    ) -> Self {
        Self {
            constructor: None,
            session_password,
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
