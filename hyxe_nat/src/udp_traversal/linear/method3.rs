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
use serde::{Serialize, Deserialize};

/// Method three: "Both sides send packets with short TTL values followed by packets with long TTL
// values". Source: page 7 of https://thomaspbraun.com/pdfs/NAT_Traversal/NAT_Traversal.pdf
pub struct Method3 {
    this_node_type: RelativeNodeType,
    encrypted_config: EncryptedConfigContainer,
    #[allow(dead_code)]
    adjacent_peer_nat: NatType,
}

#[derive(Serialize, Deserialize)]
enum NatPacket {
    Syn(u32),
    SynAck,
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
        let ref sockets = sockets_init.iter().map(|r| r).collect::<Vec<&UdpSocket>>();
        // We will begin sending packets right away, assuming the pre-process synchronization occurred
        // 400ms window
        let ref encryptor = self.encrypted_config;

        let receiver_task = async move {
            let futures_iter = sockets.into_iter().enumerate().zip(endpoints.into_iter()).map(|((idx, socket), endpoint)| tokio::time::timeout(Duration::from_millis(2000), Self::recv_until(idx, socket, endpoint, encryptor)))
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
            let ttl = 2;
            let ref syn_packet = bincode2::serialize(&NatPacket::Syn(ttl)).unwrap();
            for sck in sockets {
                // set TTL low
                sck.set_ttl(ttl).map_err(|err| FirewallError::HolePunch(err.to_string()))?;
                messages_syn.push(encryptor.generate_packet(syn_packet))
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

            let mut messages_syn = Vec::with_capacity(sockets.len());
            let ttl = 120;
            let ref syn_packet = bincode2::serialize(&NatPacket::Syn(ttl)).unwrap();
            // set TTL long. 400ms window
            for sck in sockets {
                sck.set_ttl(ttl).map_err(|err| FirewallError::HolePunch(err.to_string()))?;
                messages_syn.push(encryptor.generate_packet(syn_packet))
            }

            let mut iter = tokio::time::interval(Duration::from_millis(20));
            for _ in 0..5 {
                let _ = iter.tick().await;
                for ((socket, endpoint), message) in sockets.iter().zip(endpoints.iter()).zip(messages_syn.iter()) {
                    log::info!("Sending long TTL {:?} to {}", &message, endpoint);
                    socket.send_to(&message, endpoint).await.map_err(|err| FirewallError::HolePunch(err.to_string()))?;
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

    // Handles the reception of packets, as well as sending/awaiting for a verification
    async fn recv_until(idx: usize, socket: &UdpSocket, endpoint: &SocketAddr, encryptor: &EncryptedConfigContainer) -> Result<(usize, HolePunchedSocketAddr), FirewallError> {
        let buf = &mut [0u8; 4096];
        log::info!("[Hole-punch] Listening on {:?}", socket.local_addr().unwrap());

        let mut recv_from_required = None;
        while let Ok((len, nat_addr)) = socket.recv_from(buf).await {
            log::info!("[Hole-punch] RECV packet from {:?}", &nat_addr);
            let packet = match encryptor.decrypt_packet(&buf[..len]) {
                Some(plaintext) => plaintext,
                _ => {
                    log::warn!("BAD Hole-punch packet: decryption failed!");
                    continue;
                }
            };

            let packet: NatPacket = bincode2::deserialize(&packet).map_err(|err| FirewallError::HolePunch(err.to_string()))?;
            match packet {
                NatPacket::Syn(ttl) => {
                    log::info!("RECV SYN");
                    //if recv_from_required.is_none() {
                        log::info!("Received TTL={} packet. Awaiting mutual recognition...", ttl);
                        recv_from_required = Some(nat_addr);
                        // we received a packet, but, need to verify
                        let syn_ack = encryptor.generate_packet(&bincode2::serialize(&NatPacket::SynAck).unwrap());
                        for _ in 0..3 {
                            socket.send_to(&syn_ack, *endpoint).await?;
                        }
                    //}
                }

                NatPacket::SynAck => {
                    log::info!("RECV SYN_ACK");
                    if let Some(required_addr_in_conv) = recv_from_required {
                        if required_addr_in_conv == nat_addr {
                            // this means there was a successful ping-pong. We can now assume this communications line is valid since the nat addrs match
                            let initial_socket = endpoint;
                            let hole_punched_addr = HolePunchedSocketAddr::new(*initial_socket, nat_addr);
                            log::info!("***UDP Hole-punch to {:?} success!***", &hole_punched_addr);
                            return Ok((idx, hole_punched_addr));
                        } else {
                            log::warn!("Received SynAck, but the addrs did not match!");
                        }
                    } else {
                        log::warn!("Received SynAck, but have not yet received Syn")
                    }
                }
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