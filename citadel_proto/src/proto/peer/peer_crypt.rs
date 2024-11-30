/*!
# Peer Cryptography Module

This module implements the cryptographic key exchange and NAT traversal functionality for peer-to-peer connections in the Citadel Protocol.

## Features
- **Key Exchange Protocol**: Implements a multi-stage key exchange process
- **NAT Traversal Support**: Provides NAT type detection and compatibility checking
- **TLS Integration**: Supports TLS domain configuration for secure connections
- **Security Settings**: Configurable security levels and UDP modes
- **STUN/TURN Support**: Automatic TURN server fallback for incompatible NATs

## Core Components
- `KeyExchangeProcess`: Manages the stages of peer key exchange
- `PeerNatInfo`: Handles NAT-related information and compatibility
- `TlsDomain`: Configures TLS settings for secure connections

## Example Usage
```rust
// Stage 0: Alice initiates key exchange
let stage0 = KeyExchangeProcess::Stage0(
    public_key,
    security_settings,
    udp_mode
);

// Stage 1: Bob responds with encrypted data
let stage1 = KeyExchangeProcess::Stage1(
    ciphertext,
    Some(peer_nat_info),
    file_transfer_compatible
);

// Check NAT compatibility
let (needs_turn, addr) = peer_nat_info.generate_proper_listener_connect_addr(
    &local_nat_type
);
```

## Important Notes
1. Key exchange follows a three-stage protocol for security
2. NAT compatibility is checked before direct connections
3. TURN servers are used as fallback for incompatible NATs
4. TLS domains ensure secure communication channels

## Related Components
- `p2p_conn_handler`: Manages peer connections
- `hole_punch_compat_sink_stream`: Handles hole punching
- `session`: Manages connection sessions
- `state_container`: Tracks connection state

*/

use crate::proto::node::TlsDomain;
use citadel_types::proto::SessionSecuritySettings;
use citadel_types::proto::UdpMode;
use citadel_wire::nat_identification::NatType;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum KeyExchangeProcess {
    // alice sends public key
    Stage0(Vec<u8>, SessionSecuritySettings, UdpMode),
    // Bob sends ciphertext, addr, file transfer compatibility
    Stage1(Vec<u8>, Option<PeerNatInfo>, bool),
    // Alice sends a sync time over. Server takes care of external addr. Includes file transfer compat
    Stage2(i64, Option<PeerNatInfo>, bool),
    // The hole-punch failed
    HolePunchFailed,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerNatInfo {
    // This is the location of the listener for the other peer as obtained by the central server
    pub peer_remote_addr_visible_from_server: SocketAddr,
    pub peer_nat: NatType,
    pub tls_domain: TlsDomain,
}

impl PeerNatInfo {
    pub fn generate_proper_listener_connect_addr(
        &self,
        local_nat_type: &NatType,
    ) -> (bool, SocketAddr) {
        //let predicted_addr = self.peer_nat.predict_external_addr_from_local_bind_port(self.peer_unnated_listener_port).map(|r| SocketAddr::new(self.peer_remote_ip, r.port())).unwrap_or_else(|| SocketAddr::new(self.peer_remote_ip, self.peer_unnated_listener_port));
        let predicted_addr = self.peer_remote_addr_visible_from_server;
        // TODO: This assumes same IP, Port as visible from server. For EDM's w/delta,
        // we need to *ensure* the dualstack udp hole puncher can already handle deltas
        // properly
        let needs_turn = !self.peer_nat.stun_compatible(local_nat_type);
        (needs_turn, predicted_addr)
    }
}
