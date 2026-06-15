//! Channel plumbing for [`StateContainerInner`]: UDP channel install/removal,
//! ordered/unordered data forwarding, and C2S virtual-connection setup.

use super::includes::*;

impl<R: Ratchet> StateContainerInner<R> {
    /// This assumes the data has reached its destination endpoint, and must be forwarded to the channel
    /// (thus bypassing the unordered kernel)
    pub fn forward_data_to_ordered_channel(
        &self,
        target_cid: u64,
        group_id: u64,
        data: RatchetMessage<MessengerLayerOrderedMessage<UserMessage>>,
    ) -> Result<(), NetworkError> {
        // `&self`: the OrderedChannel is interior-mutable, so per-vconn ordered delivery only needs a
        // read lock on the StateContainer — concurrent vconns no longer serialize on the write lock.
        let endpoint_container = self.get_endpoint_container(target_cid)?;
        endpoint_container
            .to_ordered_local_channel
            .on_packet_received(group_id, data)
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }

    /// This assumes the data has reached its destination endpoint, and must be forwarded to the channel
    /// (thus bypassing the unordered kernel)
    pub fn forward_data_to_unordered_channel(&self, target_cid: u64, data: SecBuffer) -> bool {
        if let Some(vconn) = self.active_virtual_connections.get(&target_cid) {
            if let Some(channel) = vconn.endpoint_container.as_ref() {
                if let Some(unordered_channel) = channel.to_unordered_local_channel.as_ref() {
                    return unordered_channel.to_channel.unbounded_send(data).is_ok();
                }
            }
        }

        log::warn!(target: "citadel", "Attempted to forward data to unordered channel, but, one or more containers were not present");

        false
    }

    // Requirements: A TCP/reliable ordered conn channel must already be setup in order for the connection to continue
    pub fn insert_udp_channel(
        &mut self,
        target_cid: u64,
        v_conn: VirtualConnectionType,
        ticket: Ticket,
        to_udp_stream: OutboundUdpSender,
        stopper_tx: citadel_io::tokio::sync::oneshot::Sender<()>,
    ) -> Option<UdpChannel<R>> {
        if let Some(p2p_container) = self.active_virtual_connections.get_mut(&target_cid) {
            if let Some((sender, _)) = p2p_container.sender.as_mut() {
                *sender = Some(to_udp_stream.clone());
                if let Some(p2p_endpoint_container) = p2p_container.endpoint_container.as_mut() {
                    let (to_channel, rx) = unbounded();
                    // Build disconnect token from the vconn's p2p_connection_id
                    let disconnect_token = match v_conn {
                        VirtualConnectionType::LocalGroupPeer { session_cid, .. } => {
                            Some(DisconnectToken {
                                cid: session_cid,
                                connection_id: p2p_container.p2p_connection_id,
                            })
                        }
                        _ => None,
                    };
                    let udp_channel = UdpChannel::new(
                        to_udp_stream,
                        rx,
                        target_cid,
                        v_conn,
                        ticket,
                        p2p_container.is_active.clone(),
                        self.node_remote.clone(),
                        disconnect_token,
                    );
                    p2p_endpoint_container.to_unordered_local_channel =
                        Some(UnorderedChannelContainer {
                            to_channel,
                            stopper_tx,
                        });
                    // data can now be forwarded
                    Some(udp_channel)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn remove_udp_channel(&mut self, target_cid: u64) {
        if let Some(p2p_container) = self.active_virtual_connections.get_mut(&target_cid) {
            if let Some((sender, _)) = p2p_container.sender.as_mut() {
                if let Some(p2p_endpoint_container) = p2p_container.endpoint_container.as_mut() {
                    if let Some(channel) = p2p_endpoint_container.to_unordered_local_channel.take()
                    {
                        let _ = channel.stopper_tx.send(());
                    }
                    *sender = None;
                }
            }
        }
    }

    /// This should be ran at the beginning of a session to provide ordered delivery to clients
    #[allow(unused_results)]
    pub fn init_new_c2s_virtual_connection<T: PlatformOps>(
        &mut self,
        cnac: &ClientNetworkAccount<R, R>,
        channel_ticket: Ticket,
        session_cid: u64,
        session: &CitadelSession<R, T>,
    ) -> PeerChannel<R> {
        let security_settings = self
            .session_security_settings
            .expect("Should be set at beginning of session or on first SYN packet");
        // Reuse the latest one. During SYN/SYN_ACK process, toolsets should be reset inside the endpoint_crypto
        let endpoint_crypto = cnac.get_session_crypto().clone();

        let channel = self
            .create_virtual_connection(
                security_settings,
                channel_ticket,
                C2S_IDENTITY_CID,
                VirtualConnectionType::LocalGroupServer { session_cid },
                endpoint_crypto,
                session,
                true,
                Ticket(0), // C2S connections don't need P2P connection IDs
            )
            .expect("C2S connections never hit simultaneous connect guard");

        let p2p_remote = DirectP2PRemote {
            stopper: None,
            p2p_primary_stream: session
                .to_primary_stream
                .clone()
                .expect("Should be set at beginning of session or on first SYN packet"),
            from_listener: false,
        };

        // C2S connections don't have simultaneous connect races, so pass implcid=0
        self.insert_direct_p2p_connection(p2p_remote, C2S_IDENTITY_CID, 0, None)
            .expect("C2S insertion should not fail");

        if let Some(udp_alerter) = self.tcp_loaded_status.take() {
            let _ = udp_alerter.send(());
        }

        channel
    }

    pub fn setup_tcp_alert_if_udp_c2s(&mut self) -> citadel_io::tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();
        self.tcp_loaded_status = Some(tx);
        rx
    }
}
