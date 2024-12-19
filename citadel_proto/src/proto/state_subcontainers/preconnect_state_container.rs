/*!
# Pre-connection State Container Module

This module manages the state of pre-connection setup in the Citadel Protocol, handling initial handshakes and cryptographic setup.

## Features
- **Stage Tracking**: Manages pre-connection stages
- **Node Type Management**: Handles different node types
- **Cryptographic Setup**: Manages ratchet construction
- **UDP Channel Setup**: Handles UDP channel initialization
- **Ticket Management**: Tracks connection tickets

## Core Components
- `PreConnectState`: Main structure for pre-connection state
- `UdpChannelSender`: Manages UDP channel communication
- `StackedRatchetConstructor`: Handles cryptographic setup
- `NodeType`: Configures node behavior

## Example Usage
```rust
use citadel_proto::proto::state_subcontainers::PreConnectState;

// Create new pre-connection state
let mut state = PreConnectState::default();

// Handle packet reception
state.on_packet_received();

// Check connection success
if state.success {
    // Handle successful pre-connection
}

// Access generated ratchet
if let Some(ratchet) = state.generated_ratchet {
    // Use the ratchet for encryption
}
```

## Important Notes
1. Pre-connection state is critical for secure setup
2. UDP channels are managed through oneshot channels
3. Ratchet construction must complete before connection
4. Node types affect connection behavior

## Related Components
- `connect_state_container`: Handles main connection
- `peer_kem_state_container`: Manages key exchange
- `packet_processor`: Uses pre-connection state
- `state_container`: Parent state management

*/

use crate::proto::packet_processor::includes::Instant;
use crate::proto::peer::channel::UdpChannel;
use crate::proto::remote::Ticket;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::oneshot::{channel, Receiver, Sender};
use citadel_wire::hypernode_type::NodeType;

/// For keeping track of the pre-connect state
pub struct PreConnectState<R: Ratchet> {
    pub(crate) last_stage: u8,
    #[allow(dead_code)]
    pub(crate) adjacent_node_type: Option<NodeType>,
    // This entropy_bank should be turned .into() the next toolset once the other side updated
    pub(crate) constructor: Option<R::Constructor>,
    pub(crate) ticket: Option<Ticket>,
    pub(crate) last_packet_time: Option<Instant>,
    pub(crate) udp_channel_oneshot_tx: UdpChannelSender,
    pub(crate) success: bool,
    pub(crate) generated_ratchet: Option<R>,
}

impl<R: Ratchet> PreConnectState<R> {
    pub fn on_packet_received(&mut self) {
        self.last_packet_time = Some(Instant::now());
    }
}

impl<R: Ratchet> Default for PreConnectState<R> {
    fn default() -> Self {
        Self {
            generated_ratchet: None,
            udp_channel_oneshot_tx: UdpChannelSender::empty(),
            constructor: None,
            last_packet_time: None,
            last_stage: 0,
            adjacent_node_type: None,
            success: false,
            ticket: None,
        }
    }
}

pub struct UdpChannelSender {
    pub tx: Option<Sender<UdpChannel>>,
    pub rx: Option<Receiver<UdpChannel>>,
}

impl UdpChannelSender {
    pub(crate) fn empty() -> Self {
        Self { tx: None, rx: None }
    }
}

impl Default for UdpChannelSender {
    fn default() -> Self {
        let (tx, rx) = channel();
        Self {
            tx: Some(tx),
            rx: Some(rx),
        }
    }
}
