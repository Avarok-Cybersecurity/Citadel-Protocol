use std::collections::HashMap;
use std::net::SocketAddr;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Duration;


use crate::error::FirewallError;
use crate::udp_traversal::targetted_udp_socket_addr::TargettedSocketAddr;
use crate::udp_traversal::HolePunchID;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::udp_traversal::linear::LinearUdpHolePunchImpl;
use netbeam::sync::RelativeNodeType;

/// Method three: "Both sides send packets with short TTL values followed by packets with long TTL
// values". Source: page 7 of https://thomaspbraun.com/pdfs/NAT_Traversal/NAT_Traversal.pdf
pub struct Method3 {
    this_node_type: RelativeNodeType,
    encrypted_config: EncryptedConfigContainer,
    unique_id: HolePunchID,
    // in the case the adjacent node for id=key succeeds, yet, this node fails, recovery mode can ensue
    observed_addrs_on_syn: Mutex<HashMap<HolePunchID, TargettedSocketAddr>>,
    // for sending SYNs to a receiver that allow for faster Hole-punch resolutions as mediated by the controller
    // local_id, peer_id, addr
    syn_observer: UnboundedSender<(HolePunchID, HolePunchID, TargettedSocketAddr)>
}

#[derive(Serialize, Deserialize)]
enum NatPacket {
    Syn(HolePunchID, u32),
    // contains the local bind addr of candidate for socket identification
    SynAck(HolePunchID),
}


impl Method3 {
    /// Make sure to complete the pre-process stage before calling this
    pub fn new(this_node_type: RelativeNodeType, encrypted_config: EncryptedConfigContainer, unique_id: HolePunchID, syn_observer: UnboundedSender<(HolePunchID, HolePunchID, TargettedSocketAddr)>) -> Self {
        Self { this_node_type, encrypted_config, unique_id, observed_addrs_on_syn: Mutex::new(HashMap::new()), syn_observer }
    }

    /// The initiator must pass a vector correlating to the target endpoints. Each provided socket will attempt to reach out to the target endpoint (1-1)
    ///
    /// Note! The endpoints should be the port-predicted addrs
    async fn execute_either(&self, socket: &UdpSocket, endpoints: &Vec<SocketAddr>) -> Result<TargettedSocketAddr, FirewallError> {
        let default_ttl = socket.ttl().ok();
        let ref unique_id = self.unique_id.clone();
        // We will begin sending packets right away, assuming the pre-process synchronization occurred
        // 400ms window
        let ref encryptor = self.encrypted_config;
        let ref observed_addrs_on_syn = self.observed_addrs_on_syn;
        let ref syn_observer = self.syn_observer;

        const MILLIS_DELTA: u64 = 40;

        let receiver_task = async move {
            // we are only interested in the first receiver to receive a value
            if let Ok(res) = tokio::time::timeout(Duration::from_millis(2000), Self::recv_until(socket, &endpoints[0], encryptor, unique_id, observed_addrs_on_syn, syn_observer, MILLIS_DELTA)).await.map_err(|err| FirewallError::HolePunch(err.to_string()))? {
                Ok(res)
            } else {
                Err(FirewallError::HolePunch("No UDP penetration detected".to_string()))
            }
        };

        let sender_task = async move {
            tokio::time::sleep(Duration::from_millis(10)).await; // wait to allow time for the joined receiver task to execute
            Self::send_syn_barrage(2, None, socket, endpoints, encryptor, MILLIS_DELTA, 5, unique_id.clone()).await.map_err(|err| FirewallError::HolePunch(err.to_string()))?;
            Self::send_syn_barrage(120, None, socket, endpoints, encryptor,  MILLIS_DELTA, 5,unique_id.clone()).await.map_err(|err| FirewallError::HolePunch(err.to_string()))?;
            Ok(()) as Result<(), FirewallError>
        };

        let (res0, _) = tokio::join!(receiver_task, sender_task);
        let hole_punched_addr = res0?;

        if let Some(default_ttl) = default_ttl {
            socket.set_ttl(default_ttl).map_err(|err| FirewallError::HolePunch(err.to_string()))?;
        }

        log::info!("Completed hole-punch...");

        Ok(hole_punched_addr)
    }

    /// Some research papers explain that incrementing the TTL on the packet may be beneficial
    async fn send_syn_barrage(ttl_init: u32, delta_ttl: Option<u32>, socket: &UdpSocket, endpoints: &Vec<SocketAddr>, encryptor: &EncryptedConfigContainer, millis_delta: u64, count: u32, unique_id: HolePunchID) -> Result<(), anyhow::Error> {
        let mut sleep = tokio::time::interval(Duration::from_millis(millis_delta));
        let delta_ttl = delta_ttl.unwrap_or(0);
        let ttls = (0..count).into_iter().map(|idx| ttl_init + (idx*delta_ttl)).collect::<Vec<u32>>();

        let ref encryptor = EncryptedConfigContainer::default();

        // fan-out of packets from a singular source to multiple consumers using the ttls specified
        for ttl in ttls {
            let _ = socket.set_ttl(ttl);
            let _ = sleep.tick().await;
            for endpoint in endpoints {
                let packet = encryptor.generate_packet(&bincode2::serialize(&NatPacket::Syn(unique_id, ttl)).unwrap());
                log::info!("Sending TTL={} to {} || {:?}", ttl, endpoint, &packet[..] as &[u8]);
                socket.send_to(&packet, endpoint).await?;
            }
        }

        Ok(())
    }

    // Handles the reception of packets, as well as sending/awaiting for a verification
    async fn recv_until(socket: &UdpSocket, endpoint: &SocketAddr, encryptor: &EncryptedConfigContainer, unique_id: &HolePunchID, observed_addrs_on_syn: &Mutex<HashMap<HolePunchID, TargettedSocketAddr>>, syn_observer: &UnboundedSender<(HolePunchID, HolePunchID, TargettedSocketAddr)>, millis_delta: u64) -> Result<TargettedSocketAddr, FirewallError> {
        let buf = &mut [0u8; 4096];
        log::info!("[Hole-punch] Listening on {:?}", socket.local_addr().unwrap());
        let ref encryptor = EncryptedConfigContainer::default();
        //let mut recv_from_required = None;
        while let Ok((len, peer_external_addr)) = socket.recv_from(buf).await {
            log::info!("[UDP Hole-punch] RECV packet from {:?} | {:?}", &peer_external_addr, &buf[..len]);
            let packet = match encryptor.decrypt_packet(&buf[..len]) {
                Some(plaintext) => plaintext,
                _ => {
                    log::warn!("BAD Hole-punch packet: decryption failed!");
                    continue;
                }
            };


            match bincode2::deserialize(&packet).map_err(|err| FirewallError::HolePunch(err.to_string())) {
                Ok(NatPacket::Syn(peer_unique_id, ttl)) => {
                    log::info!("RECV SYN");
                    let hole_punched_addr = TargettedSocketAddr::new(*endpoint, peer_external_addr, peer_unique_id);

                    let _ = syn_observer.send((*unique_id, peer_unique_id, hole_punched_addr));
                    observed_addrs_on_syn.lock().insert(peer_unique_id, hole_punched_addr);

                    log::info!("Received TTL={} packet. Awaiting mutual recognition...", ttl);
                    let mut sleep = tokio::time::interval(Duration::from_millis(millis_delta));
                    for ttl in [20, 60, 120] {
                        let _ = socket.set_ttl(ttl);
                        sleep.tick().await;
                        socket.send_to(&encryptor.generate_packet(&bincode2::serialize(&NatPacket::SynAck(unique_id.clone())).unwrap()), peer_external_addr).await?;
                    }
                }

                // the reception of a SynAck proves the existence of a hole punched since there is bidirectional communication through the NAT
                Ok(NatPacket::SynAck(adjacent_unique_id)) => {
                    log::info!("RECV SYN_ACK");
                    // this means there was a successful ping-pong. We can now assume this communications line is valid since the nat addrs match
                    let initial_socket = endpoint;
                    let hole_punched_addr = TargettedSocketAddr::new(*initial_socket, peer_external_addr, adjacent_unique_id);
                    log::info!("***UDP Hole-punch to {:?} success!***", &hole_punched_addr);

                    return Ok(hole_punched_addr);
                }

                Err(err) => {
                    log::warn!("Unable to deserialize packet {:?} from {:?}: {:?}", &packet[..], peer_external_addr, err);
                }
            }
        }

        Err(FirewallError::HolePunch("Socket recv error".to_string()))
    }
}

#[async_trait]
impl LinearUdpHolePunchImpl for Method3 {
    async fn execute(&self, socket: &UdpSocket, endpoints: &Vec<SocketAddr>) -> Result<TargettedSocketAddr, FirewallError> {
        match self.this_node_type {
            RelativeNodeType::Initiator => {
                self.execute_either(socket, endpoints).await
            }

            RelativeNodeType::Receiver => {
                self.execute_either(socket, endpoints).await
            }
        }
    }

    fn get_peer_external_addr_from_peer_hole_punch_id(&self, id: HolePunchID) -> Option<TargettedSocketAddr> {
        let lock = self.observed_addrs_on_syn.lock();
        log::info!("Recv'd SYNS: {:?}", &*lock);
        lock.get(&id).cloned()
    }

    fn get_all_received_peer_hole_punched_ids(&self) -> Vec<HolePunchID> {
        self.observed_addrs_on_syn.lock().keys().copied().collect()
    }
}