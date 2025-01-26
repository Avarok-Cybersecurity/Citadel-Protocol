/*!
# Peer Module

This module is the root of the peer-to-peer networking implementation in the Citadel Protocol, organizing various submodules for P2P functionality.

## Features
- **Complete P2P Stack**: Provides a full peer-to-peer networking solution
- **Modular Architecture**: Separates concerns into specialized submodules
- **Security-First Design**: Implements secure communication patterns
- **NAT Traversal**: Supports various NAT traversal techniques
- **Group Communication**: Enables secure group messaging

## Submodules
- `peer_layer`: Core peer networking infrastructure and state management
- `channel`: Basic peer-to-peer communication channels
- `group_channel`: Group communication channels
- `peer_crypt`: Cryptographic operations and key exchange
- `message_group`: Group messaging framework
- `p2p_conn_handler`: Direct P2P connection management
- `hole_punch_compat_sink_stream`: NAT traversal compatibility layer

## Important Notes
1. All peer communication is encrypted by default
2. NAT traversal is handled automatically
3. Group messaging follows a consent-based model
4. Connection state is managed through the peer layer

## Related Components
- `session`: Manages connection sessions
- `packet_processor`: Handles packet routing
- `state_container`: Tracks connection state
- `remote`: Manages remote connections

*/

/// For managing the state of peer-related activities
pub mod peer_layer;

pub mod channel;

pub mod group_channel;

pub mod peer_crypt;

pub mod message_group;

pub mod p2p_conn_handler;

pub(crate) mod hole_punch_compat_sink_stream;
