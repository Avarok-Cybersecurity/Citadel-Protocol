use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::SocketAddr;

use citadel_io::tokio::net::UdpSocket;
use citadel_io::tokio::sync::Mutex as TokioMutex;
use citadel_io::tokio::time::Duration;
use serde::{Deserialize, Serialize};

use crate::error::FirewallError;
use crate::socket_helpers::ensure_ipv6;
use crate::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use crate::udp_traversal::targetted_udp_socket_addr::TargettedSocketAddr;
use crate::udp_traversal::HolePunchID;
use citadel_io::Mutex;
use netbeam::sync::RelativeNodeType;
use std::sync::Arc;

/// Method three: "Both sides send packets with short TTL values followed by packets with long TTL
// values". Source: page 7 of https://thomaspbraun.com/pdfs/NAT_Traversal/NAT_Traversal.pdf
pub struct Method3 {
    this_node_type: RelativeNodeType,
    encrypted_config: HolePunchConfigContainer,
    unique_id: HolePunchID,
    // in the case the adjacent node for id=key succeeds, yet, this node fails, recovery mode can ensue
    observed_addrs_on_syn: Mutex<HashMap<HolePunchID, TargettedSocketAddr>>,
}

#[derive(Serialize, Deserialize)]
enum NatPacket {
    Syn(HolePunchID, u32, RelativeNodeType, SocketAddr),
    // contains the local bind addr of candidate for socket identification
    SynAck(HolePunchID, RelativeNodeType, SocketAddr, HolePunchID),
    Check,
}

impl Method3 {
    /// Make sure to complete the pre-process stage before calling this
    pub fn new(
        this_node_type: RelativeNodeType,
        encrypted_config: HolePunchConfigContainer,
        unique_id: HolePunchID,
    ) -> Self {
        Self {
            this_node_type,
            encrypted_config,
            unique_id,
            observed_addrs_on_syn: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn execute(
        &self,
        socket: &UdpSocket,
        endpoints: &[SocketAddr],
    ) -> Result<TargettedSocketAddr, FirewallError> {
        match self.this_node_type {
            RelativeNodeType::Initiator => self.execute_either(socket, endpoints).await,
            RelativeNodeType::Receiver => self.execute_either(socket, endpoints).await,
        }
    }

    pub(crate) fn get_peer_external_addr_from_peer_hole_punch_id(
        &self,
        id: HolePunchID,
    ) -> Option<TargettedSocketAddr> {
        let lock = self.observed_addrs_on_syn.lock();
        log::trace!(target: "citadel", "Recv'd SYNS: {:?}", &*lock);
        lock.get(&id).copied()
    }

    /// The initiator must pass a vector correlating to the target endpoints. Each provided socket will attempt to reach out to the target endpoint (1-1)
    ///
    /// Note! The endpoints should be the port-predicted addrs
    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err(Debug))
    )]
    async fn execute_either(
        &self,
        socket: &UdpSocket,
        endpoints: &[SocketAddr],
    ) -> Result<TargettedSocketAddr, FirewallError> {
        let default_ttl = socket.ttl().ok();
        log::trace!(target: "citadel", "Default TTL: {:?}", default_ttl);
        let unique_id = &self.unique_id.clone();
        let this_node_type = self.this_node_type;
        // We will begin sending packets right away, assuming the pre-process synchronization occurred
        // 400ms window
        let encryptor = &self.encrypted_config;
        let observed_addrs_on_syn = &self.observed_addrs_on_syn;

        let socket_wrapper = &UdpWrapper::new(socket);

        const MILLIS_DELTA: u64 = 20;
        let packet_send_params = &SendPacketBarrageParams {
            ttl_init: 20,
            delta_ttl: Some(60),
            socket: socket_wrapper,
            endpoints: &tokio::sync::Mutex::new(endpoints.iter().copied().collect()),
            encryptor,
            millis_delta: MILLIS_DELTA,
            count: 2,
            unique_id: *unique_id,
            this_node_type,
        };

        let receiver_task = async move {
            // we are only interested in the first receiver to receive a value
            let timeout = citadel_io::tokio::time::timeout(
                Duration::from_millis(3000),
                Self::recv_until(
                    socket_wrapper,
                    encryptor,
                    unique_id,
                    observed_addrs_on_syn,
                    MILLIS_DELTA,
                    this_node_type,
                    packet_send_params,
                ),
            );

            timeout.await.unwrap_or_else(|_| {
                Err(FirewallError::HolePunch(
                    "Timeout while waiting for UDP penetration".to_string(),
                ))
            })
        };

        let sender_task = async move {
            //citadel_io::tokio::time::sleep(Duration::from_millis(10)).await; // wait to allow time for the joined receiver task to execute
            Self::send_packet_barrage(packet_send_params, None)
                .await
                .map_err(|err| FirewallError::HolePunch(err.to_string()))?;
            Ok(()) as Result<(), FirewallError>
        };

        let (res0, res1) = citadel_io::tokio::join!(receiver_task, sender_task);

        log::trace!(target: "citadel", "Hole-punch join result: recv={:?} and send={:?}", res0, res1);

        if let Some(default_ttl) = default_ttl {
            let _ = socket
                .set_ttl(default_ttl)
                .map_err(|err| FirewallError::HolePunch(err.to_string()));
        }

        let hole_punched_addr = res0?;

        log::trace!(target: "citadel", "Completed hole-punch...");

        Ok(hole_punched_addr)
    }

    /// Some research papers explain that incrementing the TTL on the packet may be beneficial
    #[allow(clippy::too_many_arguments)]
    async fn send_packet_barrage(
        params: &SendPacketBarrageParams<'_>,
        syn_received_addr: Option<(SocketAddr, HolePunchID)>,
    ) -> Result<(), anyhow::Error> {
        let SendPacketBarrageParams {
            ttl_init,
            delta_ttl,
            socket,
            endpoints,
            encryptor,
            millis_delta,
            count,
            unique_id,
            this_node_type,
        } = params;

        let mut sleep = citadel_io::tokio::time::interval(Duration::from_millis(*millis_delta));
        let delta_ttl = delta_ttl.unwrap_or(0);
        let ttls = (0..*count)
            .map(|idx| ttl_init + (idx * delta_ttl))
            .collect::<Vec<u32>>();

        // fan-out all packets from a singular source to multiple consumers using the ttls specified
        for ttl in ttls {
            let _ = sleep.tick().await;

            let mut endpoints_lock = endpoints.lock().await;

            for endpoint in endpoints_lock.clone() {
                let packet_ty = if let Some((syn_addr, peer_id_recv)) = syn_received_addr {
                    // put the addr the peer used to send to this node, that way the peer knows where
                    // to send the packet, even if the receive address is translated
                    NatPacket::SynAck(*unique_id, *this_node_type, syn_addr, peer_id_recv)
                } else {
                    // put the endpoint we are sending to in the payload, that way, once we get a SynAck, we know
                    // where our sent packet was sent that worked
                    NatPacket::Syn(*unique_id, ttl, *this_node_type, endpoint)
                    // SynAck
                };

                let packet_plaintext = bincode::serialize(&packet_ty).unwrap();

                let packet = encryptor.generate_packet(&packet_plaintext);
                log::trace!(target: "citadel", "Sending TTL={} to {} || {:?}", ttl, endpoint, &packet[..] as &[u8]);
                match socket.send(&packet, endpoint, Some(ttl)).await {
                    Ok(can_continue) => {
                        if !can_continue {
                            log::trace!(target: "citadel", "Early-terminating SYN barrage");
                            return Ok(());
                        }
                    }
                    Err(err) => {
                        let err_kind = err.kind();
                        if err_kind != ErrorKind::AddrNotAvailable {
                            log::warn!(target: "citadel", "Error sending packet from {:?} to {endpoint}: {:?}", socket.socket.local_addr()?, err);
                        }

                        if err.to_string().contains("NetworkUnreachable") {
                            endpoints_lock.remove(&endpoint);
                        }

                        if err_kind == ErrorKind::InvalidInput {
                            endpoints_lock.remove(&endpoint);
                        }
                    }
                }
            }

            if endpoints_lock.is_empty() {
                log::warn!(target: "citadel", "No endpoints to send to for {unique_id:?} (local bind: {})", socket.socket.local_addr()?);
                return Err(anyhow::Error::msg(
                    "All UDP endpoints are unreachable for NAT traversal",
                ));
            }
        }

        Ok(())
    }

    // Handles the reception of packets, as well as sending/awaiting for a verification
    async fn recv_until(
        socket: &UdpWrapper<'_>,
        encryptor: &HolePunchConfigContainer,
        unique_id: &HolePunchID,
        observed_addrs_on_syn: &Mutex<HashMap<HolePunchID, TargettedSocketAddr>>,
        _millis_delta: u64,
        this_node_type: RelativeNodeType,
        send_packet_params: &SendPacketBarrageParams<'_>,
    ) -> Result<TargettedSocketAddr, FirewallError> {
        let buf = &mut [0u8; 4096];
        log::trace!(target: "citadel", "[Hole-punch] Listening on {:?}", socket.socket.local_addr()?);

        let mut has_received_syn = false;
        loop {
            match socket.recv_from(buf).await {
                Ok((len, peer_external_addr)) => {
                    log::trace!(target: "citadel", "[UDP Hole-punch] RECV packet from {:?} | {:?}", &peer_external_addr, &buf[..len]);
                    let packet = match encryptor.decrypt_packet(&buf[..len]) {
                        Some(plaintext) => plaintext,
                        _ => {
                            log::warn!(target: "citadel", "BAD Hole-punch packet: decryption failed!");
                            continue;
                        }
                    };

                    match bincode::deserialize(&packet)
                        .map_err(|err| FirewallError::HolePunch(err.to_string()))
                    {
                        Ok(NatPacket::Check) => {
                            continue;
                        }
                        Ok(NatPacket::Syn(
                            peer_unique_id,
                            ttl,
                            adjacent_node_type,
                            their_send_addr,
                        )) => {
                            if has_received_syn {
                                continue;
                            }

                            if adjacent_node_type == this_node_type || &peer_unique_id == unique_id
                            {
                                log::warn!(target: "citadel", "RECV loopback packet; will discard");
                                continue;
                            }

                            log::trace!(target: "citadel", "RECV SYN from {:?}", peer_unique_id);
                            let hole_punched_addr = TargettedSocketAddr::new(
                                peer_external_addr,
                                peer_external_addr,
                                peer_unique_id,
                            );

                            observed_addrs_on_syn
                                .lock()
                                .insert(peer_unique_id, hole_punched_addr);
                            log::trace!(target: "citadel", "Received TTL={} packet from {:?}. Awaiting mutual recognition... ", ttl, peer_external_addr);

                            has_received_syn = true;

                            let mut lock = send_packet_params.endpoints.lock().await;
                            let send_addrs = std::iter::once(peer_external_addr)
                                .chain(lock.iter().copied())
                                .collect::<HashSet<SocketAddr>>();
                            *lock = send_addrs;
                            drop(lock);

                            Self::send_packet_barrage(
                                send_packet_params,
                                Some((their_send_addr, peer_unique_id)),
                            )
                            .await
                            .map_err(|err| FirewallError::HolePunch(err.to_string()))?;
                        }

                        // the reception of a SynAck proves the existence of a hole punched since there is bidirectional communication through the NAT
                        Ok(NatPacket::SynAck(
                            adjacent_unique_id,
                            adjacent_node_type,
                            address_we_sent_to,
                            our_id,
                        )) => {
                            log::trace!(target: "citadel", "RECV SYN_ACK");
                            if adjacent_node_type == this_node_type {
                                log::warn!(target: "citadel", "RECV self-referential packet; will discard");
                                continue;
                            }

                            if &our_id != unique_id {
                                log::warn!(target: "citadel", "RECV Packet from wrong hole punching process. Received {our_id:?}, But expected our id of {unique_id:?}");
                                continue;
                            }

                            // NOTE: it is entirely possible that we receive a SynAck before even getting a Syn.
                            // Since we send SYNs to the other node, and, it's possible that we don't receive a SYN by the time
                            // the other node ACKs our sent out SYN, we should not terminate.

                            if peer_external_addr != address_we_sent_to {
                                let packet = bincode::serialize(&NatPacket::Check).unwrap();
                                // See if we can send a packet to the addr
                                if socket
                                    .socket
                                    .send_to(&packet, peer_external_addr)
                                    .await
                                    .is_ok()
                                {
                                    log::warn!(target: "citadel", "[will allow] RECV SYN_ACK that comes from the wrong addr. RECV: {:?}, Expected: {:?}", peer_external_addr, address_we_sent_to);
                                } else {
                                    log::warn!(target: "citadel", "[will NOT allow] RECV SYN_ACK that comes from the wrong addr. RECV: {:?}, Expected: {:?}", peer_external_addr, address_we_sent_to);
                                    continue;
                                }
                            }

                            // this means there was a successful ping-pong.
                            // initial should be address_we_went_to, natted would be peer_external_addr
                            let hole_punched_addr = TargettedSocketAddr::new(
                                address_we_sent_to,
                                peer_external_addr,
                                adjacent_unique_id,
                            );
                            log::trace!(target: "citadel", "***UDP Hole-punch to {:?} success!***", &hole_punched_addr);
                            socket.stop_outgoing_traffic().await;

                            return Ok(hole_punched_addr);
                        }

                        Err(err) => {
                            log::warn!(target: "citadel", "Unable to deserialize packet {:?} from {:?}: {:?}", &packet[..], peer_external_addr, err);
                        }
                    }
                }

                Err(err) => {
                    log::error!(
                        target: "citadel",
                        "Error receiving packet from {:?}: {err:?}",
                        socket.socket.local_addr()?
                    );

                    if err.kind() == ErrorKind::ConnectionReset {
                        return Err(FirewallError::HolePunch(
                            "Connection reset while waiting for UDP penetration".to_string(),
                        ));
                    }
                }
            }
        }
    }
}

/// Used to enforce mutual exclusion writing
struct UdpWrapper<'a> {
    lock: Arc<TokioMutex<bool>>,
    socket: &'a UdpSocket,
}

impl UdpWrapper<'_> {
    fn new(socket: &UdpSocket) -> UdpWrapper {
        UdpWrapper {
            lock: Arc::new(TokioMutex::new(true)),
            socket,
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    /// Returns false if
    async fn send(
        &self,
        buf: &[u8],
        mut to: SocketAddr,
        ttl: Option<u32>,
    ) -> std::io::Result<bool> {
        let lock = self.lock.lock().await;
        if !*lock {
            return Ok(false);
        }

        if let Some(ttl) = ttl {
            let _ = self.socket.set_ttl(ttl);
        }

        let local_addr = self.socket.local_addr()?;

        if to.is_ipv6() && local_addr.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Send_to is ipv6, but bind is ipv4",
            ));
        }

        if local_addr.is_ipv6() {
            to = SocketAddr::V6(ensure_ipv6(to))
        }

        self.socket.send_to(buf, to).await?;
        Ok(true)
    }

    async fn stop_outgoing_traffic(&self) {
        *self.lock.lock().await = false
    }
}

struct SendPacketBarrageParams<'a> {
    ttl_init: u32,
    delta_ttl: Option<u32>,
    socket: &'a UdpWrapper<'a>,
    endpoints: &'a tokio::sync::Mutex<HashSet<SocketAddr>>,
    encryptor: &'a HolePunchConfigContainer,
    millis_delta: u64,
    count: u32,
    unique_id: HolePunchID,
    this_node_type: RelativeNodeType,
}
