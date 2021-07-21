use std::iter::FromIterator;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::time::Duration;

use crate::error::FirewallError;
use crate::udp_traversal::hole_punched_udp_socket_addr::{HolePunchedSocketAddr, HolePunchedUdpSocket};
use crate::udp_traversal::linear::{LinearUdpHolePunchImpl, RelativeNodeType};
use futures::StreamExt;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::nat_identification::NatType;

/// Method three: "Both sides send packets with short TTL values followed by packets with long TTL
// values". Source: page 7 of https://thomaspbraun.com/pdfs/NAT_Traversal/NAT_Traversal.pdf
pub struct Method3 {
    this_node_type: RelativeNodeType,
    encrypted_config: EncryptedConfigContainer,
    #[allow(dead_code)]
    adjacent_peer_nat: NatType
}


impl Method3 {
    /// Make sure to complete the pre-process stage before calling this
    pub fn new(this_node_type: RelativeNodeType, encrypted_config: EncryptedConfigContainer, adjacent_peer_nat: NatType) -> Self {
        Self { this_node_type, encrypted_config, adjacent_peer_nat }
    }

    /// The initiator must pass a vector correlating to the target endpoints. Each provided socket will attempt to reach out to the target endpoint (1-1)
    ///
    /// Note! The endpoints should be the port-predicted addrs
    async fn execute_either(&self, sockets_init: &mut Vec<UdpSocket>, endpoints: &Vec<SocketAddr>) -> Result<HolePunchedUdpSocket, FirewallError> {
        let ref sockets = sockets_init.iter().map(|r|r).collect::<Vec<&UdpSocket>>();
        // We will begin sending packets right away, assuming the pre-process synchronization occurred
        // 400ms window
        let ref encryptor = self.encrypted_config;

        let receiver_task = async move {
            let futures_iter = sockets.into_iter().enumerate().zip(endpoints.into_iter()).map(|((idx, socket), endpoint)| tokio::time::timeout(Duration::from_millis(1000), Self::recv_until(idx, socket, endpoint, encryptor)))
                .collect::<Vec<_>>();

            let mut futures_ordered_concurrent = futures::stream::FuturesUnordered::from_iter(futures_iter);

            // we are only interested in the first receiver to receive a value
            if let Some(res) = futures_ordered_concurrent.next().await {
                res.map_err(|err| FirewallError::HolePunch(err.to_string()))?
            } else {
                Err(FirewallError::HolePunch("No UDP penetration detected".to_string()))
            }

        };

        let sender_task = async move {
            tokio::time::sleep(Duration::from_millis(10)).await; // wait to allow time for the joined receiver task to execute
            let mut messages_syn = Vec::with_capacity(sockets.len());
            for sck in sockets {
                // set TTL low
                sck.set_ttl(2).map_err(|err| FirewallError::HolePunch(err.to_string()))?;
                messages_syn.push(encryptor.generate_packet(sck.local_addr().map_err(|err| FirewallError::HolePunch(err.to_string()))?.port()))
            }

            let messages_syn = messages_syn.iter().map(|r| r.as_ref()).collect::<Vec<&[u8]>>();

            let mut sleep = tokio::time::interval(Duration::from_millis(20));

            for _ in 0..5 {
                let _ = sleep.tick().await;
                for ((socket, message), endpoint) in sockets.iter().zip(messages_syn.iter()).zip(endpoints.iter()) {
                    log::info!("Sending short TTL {:?} to {}", *message, endpoint);
                    socket.send_to(*message, endpoint).await.map_err(|err| FirewallError::HolePunch(err.to_string()))?;
                }
            }

            // set TTL long. 400ms window
            for sck in sockets {
                sck.set_ttl(120).map_err(|err| FirewallError::HolePunch(err.to_string()))?;
            }

            let mut iter = tokio::time::interval(Duration::from_millis(20));
            for _ in 0..5 {
                let _ = iter.tick().await;
                for ((socket, endpoint), message) in sockets.iter().zip(endpoints.iter()).zip(messages_syn.iter()) {
                    log::info!("Sending long TTL {:?} to {}", *message, endpoint);
                    socket.send_to(*message, endpoint).await.map_err(|err| FirewallError::HolePunch(err.to_string()))?;
                }
            }

            Ok(()) as Result<(), FirewallError>
        };

        let (res0, _) = tokio::join!(receiver_task, sender_task);
        let (idx, hole_punched_addr) = res0?;
        let ret = HolePunchedUdpSocket { socket: sockets_init.remove(idx), addr: hole_punched_addr };

        log::info!("Completed hole-punch...");

        Ok(ret)
    }

    // Receives until a pattern is found in the payload
    async fn recv_until(idx: usize, socket: &UdpSocket, endpoint: &SocketAddr, encryptor: &EncryptedConfigContainer) -> Result<(usize, HolePunchedSocketAddr), FirewallError> {
        let buf = &mut [0u8; 4096];
        log::info!("[Hole-punch] Listening on {:?}", socket.local_addr().unwrap());

        while let Ok((len, nat_addr)) = socket.recv_from(buf).await {
            log::info!("[Hole-punch] RECV packet from {:?}", &nat_addr);
            let packet = match encryptor.decrypt_packet(&buf[..len]) {
                Some(plaintext) => plaintext,
                _ => {
                    log::warn!("BAD Hole-punch packet: decryption failed!");
                    continue;
                }
            };

            let len = packet.len();
            if len == 2 {
                //let _private_remote_port = packet.reader().read_u16()?;
                let initial_socket = endpoint;
                let hole_punched_addr = HolePunchedSocketAddr::new(*initial_socket, nat_addr);
                log::info!("RECV Dat: {}", &hole_punched_addr);
                return Ok((idx, hole_punched_addr));
            }
        }

        Err(FirewallError::HolePunch("Socket recv error".to_string()))
    }
}

#[async_trait]
impl LinearUdpHolePunchImpl for Method3 {
    async fn execute(&self, sockets: &mut Vec<UdpSocket>, endpoints: &Vec<SocketAddr>) -> Result<HolePunchedUdpSocket, FirewallError> {
        match self.this_node_type {
            RelativeNodeType::Initiator => {
                self.execute_either(sockets, endpoints).await
            }

            RelativeNodeType::Receiver => {
                self.execute_either(sockets, endpoints).await
            }
        }
    }
}