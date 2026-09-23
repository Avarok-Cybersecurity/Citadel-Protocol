//! TURN relay client (RFC 8656 over the RFC 8489 STUN codec) for peers whose NATs defeat hole
//! punching.
//!
//! - [`config`]: the application-supplied servers, credentials, expiry and [`TurnPolicy`].
//! - [`TurnAllocation`]: Allocate (long-term credentials, REALM/NONCE handling), Refresh,
//!   CreatePermission, ChannelBind and ChannelData over a UDP, TCP or TLS client leg. The relayed
//!   leg is always UDP (RFC 6062 TCP relaying is not used).
//! - [`TurnRelaySocket`]: the allocation as a quinn [`quinn::AsyncUdpSocket`], so the P2P QUIC
//!   connection runs over the relay unchanged.
//!
//! Relayed QUIC packets are carried in ChannelData, which costs [`CHANNEL_DATA_HEADER_LEN`] bytes
//! per datagram on the client leg; `quic::RELAYED_QUIC_MTU` subtracts it so datagram budgets
//! (`OutboundUdpSender::max_payload_len`) reflect the relayed path.

pub mod config;

#[cfg(not(target_family = "wasm"))]
mod client;
#[cfg(not(target_family = "wasm"))]
mod codec;
#[cfg(not(target_family = "wasm"))]
mod driver;
#[cfg(not(target_family = "wasm"))]
mod socket;
#[cfg(not(target_family = "wasm"))]
mod transaction;
#[cfg(not(target_family = "wasm"))]
mod transport;

pub use config::{TurnPolicy, TurnRelayConfig, TurnServerCredential, TurnTransport, TurnUrl};

#[cfg(not(target_family = "wasm"))]
pub use client::TurnAllocation;
#[cfg(not(target_family = "wasm"))]
pub use codec::CHANNEL_DATA_HEADER_LEN;
#[cfg(not(target_family = "wasm"))]
pub use socket::TurnRelaySocket;

/// Learns this socket's server-reflexive address with an unauthenticated STUN Binding request
/// (RFC 8489 §6) — TURN servers answer these on their UDP port.
#[cfg(not(target_family = "wasm"))]
pub async fn reflexive_address(
    socket: &citadel_io::tokio::net::UdpSocket,
    stun_server: std::net::SocketAddr,
    timeout: std::time::Duration,
) -> std::io::Result<std::net::SocketAddr> {
    use stun::attributes::ATTR_XORMAPPED_ADDRESS;
    let tid = codec::TransactionId::new();
    let request = codec::build(
        codec::METHOD_BINDING,
        codec::CLASS_REQUEST,
        tid,
        &[],
        None,
        true,
    )?;
    socket.send_to(&request.raw, stun_server).await?;
    let mut buf = [0u8; 1500];
    citadel_io::tokio::time::timeout(timeout, async {
        loop {
            let (n, from) = socket.recv_from(&mut buf).await?;
            let Ok(m) = codec::parse(&buf[..n]) else {
                continue;
            };
            if from == stun_server && m.transaction_id.0 == tid.0 {
                return codec::xor_address(&m, ATTR_XORMAPPED_ADDRESS).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Binding response without XOR-MAPPED-ADDRESS",
                    )
                });
            }
        }
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "STUN Binding timed out"))?
}
