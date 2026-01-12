/*!
# Peer Key Exchange Management State Container Module

This module manages the state of peer-to-peer key exchange processes in the Citadel Protocol, handling cryptographic operations and security settings.

## Features
- **Key Exchange State**: Manages key exchange constructor state
- **Security Settings**: Handles session security configuration
- **UDP Channel Management**: Controls UDP communication channels
- **Initiator Role**: Tracks local peer's role in key exchange
- **Session Security**: Manages session passwords and security

## Core Components
- `PeerKemStateContainer`: Main structure for key exchange state
- `StackedRatchetConstructor`: Handles cryptographic key construction
- `SessionSecuritySettings`: Configures security parameters
- `UdpChannelSender`: Manages UDP channel communication

## Important Notes
1. Key exchange state is critical for secure communication
2. UDP channels are optional based on configuration
3. Security settings determine encryption strength
4. Session passwords must be properly managed

## Related Components
- `peer_crypt`: Handles peer encryption
- `session`: Manages session security
- `packet_processor`: Uses key exchange for packets
- `state_container`: Parent state management

*/

use crate::proto::state_subcontainers::preconnect_state_container::UdpChannelSender;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::oneshot;
use citadel_types::crypto::PreSharedKey;
use citadel_types::proto::SessionSecuritySettings;

pub struct PeerKemStateContainer<R: Ratchet> {
    pub(crate) constructor: Option<R::Constructor>,
    pub(crate) local_is_initiator: bool,
    pub(crate) session_security_settings: SessionSecuritySettings,
    pub(crate) udp_channel_sender: UdpChannelSender<R>,
    pub(crate) session_password: PreSharedKey,
    /// Cancellation signal for hole punch operations.
    /// When this container is dropped (on disconnect or failure), the sender is dropped,
    /// which cancels any in-progress hole punch operation. This prevents orphaned
    /// hole punch operations from interfering with reconnection attempts.
    pub(crate) hole_punch_cancel_tx: Option<oneshot::Sender<()>>,
}

impl<R: Ratchet> PeerKemStateContainer<R> {
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
            hole_punch_cancel_tx: None,
        }
    }
}
