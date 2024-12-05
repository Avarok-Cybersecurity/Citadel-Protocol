/*!
# Hole Punch Compatibility Stream Module

This module implements a compatibility layer for UDP hole punching in the Citadel Protocol, providing a reliable ordered stream interface for NAT traversal.

## Features
- **Stream Abstraction**: Implements `ReliableOrderedStreamToTarget` for hole punching
- **Compatibility Layer**: Bridges between different network protocols
- **Security Integration**: Incorporates stacked ratchet encryption
- **Packet Routing**: Supports both client-server and peer-to-peer routing
- **State Management**: Maintains connection state and packet ordering

## Core Components
- `ReliableOrderedCompatStream`: Main stream implementation for hole punching
- `ConnAddr`: Address management for connection endpoints
- `StackedRatchet`: Encryption layer for secure communication

## Example Usage
```rust
// Create a new compatibility stream
let compat_stream = ReliableOrderedCompatStream::new(
    primary_stream,
    state_container,
    target_cid,
    stacked_ratchet,
    security_level
);

// Send data through the stream
compat_stream.send_to_peer(&data)?;

// Receive data from the stream
let received = compat_stream.recv()?;
```

## Important Notes
1. Supports both client-server and peer-to-peer modes
2. Requires pre-loaded ratchets for P2P communication
3. Uses central node for packet routing in P2P mode
4. Maintains packet ordering and reliability

## Related Components
- `peer_crypt`: Handles encryption and key exchange
- `p2p_conn_handler`: Manages peer connections
- `state_container`: Tracks connection state
- `packet_processor`: Handles packet routing

*/

use crate::proto::outbound_sender::{OutboundPrimaryStreamSender, UnboundedReceiver};
use crate::proto::peer::p2p_conn_handler::generic_error;
use crate::proto::state_container::StateContainerInner;
use async_trait::async_trait;
use bytes::Bytes;
use citadel_crypt::stacked_ratchet::Ratchet;
use citadel_io::tokio::sync::Mutex;
use citadel_types::crypto::SecurityLevel;
use netbeam::reliable_conn::{ConnAddr, ReliableOrderedStreamToTarget};
use std::net::SocketAddr;
use std::str::FromStr;

pub(crate) struct ReliableOrderedCompatStream<R: Ratchet> {
    to_primary_stream: OutboundPrimaryStreamSender,
    from_stream: Mutex<UnboundedReceiver<Bytes>>,
    peer_external_addr: SocketAddr,
    local_bind_addr: SocketAddr,
    hr: R,
    security_level: SecurityLevel,
    target_cid: u64,
}

impl<R: Ratchet> ReliableOrderedCompatStream<R> {
    /// For C2S, using this is straight forward (set target_cid to 0)
    /// For P2P, using this is not as straight forward. This will use the central node for routing packets. As such, the target_cid must be set to the peers to enable routing. Additionally, this will need to use the p2p ratchet. This implies that
    /// BOTH nodes must already have the ratchets loaded
    pub(crate) fn new(
        to_primary_stream: OutboundPrimaryStreamSender,
        state_container: &mut StateContainerInner<R>,
        target_cid: u64,
        hr: R,
        security_level: SecurityLevel,
    ) -> Self {
        let (from_stream_tx, from_stream_rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();

        // insert from_stream_tx into state container so that the protocol can deliver packets to the hole puncher
        // NOTE: The protocol must strip the header when passing packets to the from_stream function!
        let _ = state_container
            .hole_puncher_pipes
            .insert(target_cid, from_stream_tx);
        // NOTE: this is hacky. We don't actually need real addrs here since this is used for hole punching
        let peer_external_addr = SocketAddr::from_str("1.2.3.4:1234").unwrap();
        let local_bind_addr = SocketAddr::from_str("0.0.0.0:1234").unwrap();
        Self {
            to_primary_stream,
            from_stream: Mutex::new(from_stream_rx),
            peer_external_addr,
            local_bind_addr,
            hr,
            security_level,
            target_cid,
        }
    }
}

#[async_trait]
impl<R: Ratchet> ReliableOrderedStreamToTarget for ReliableOrderedCompatStream<R> {
    async fn send_to_peer(&self, input: &[u8]) -> std::io::Result<()> {
        let packet = crate::proto::packet_crafter::hole_punch::generate_packet(
            &self.hr,
            input,
            self.security_level,
            self.target_cid,
        );
        self.to_primary_stream
            .unbounded_send(packet)
            .map_err(|err| generic_error(err.to_string()))
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        // This assumes the payload is stripped from the header and the payload is decrypted
        // packet is decrypted in hole_punch.rs
        self.from_stream
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| generic_error("Inbound ordered reliable stream died"))
    }
}

impl<R: Ratchet> ConnAddr for ReliableOrderedCompatStream<R> {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_bind_addr)
    }
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer_external_addr)
    }
}
