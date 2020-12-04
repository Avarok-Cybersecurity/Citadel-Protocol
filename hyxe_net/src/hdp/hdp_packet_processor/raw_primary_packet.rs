use super::includes::*;
use bytes::BytesMut;

/// For primary-port packet types. NOT for wave ports
pub fn process(this_implicated_cid: Option<u64>, session: &HdpSession, remote_peer: SocketAddr, local_primary_port: u16, packet: BytesMut) -> PrimaryProcessorResult {
    let packet = HdpPacket::new_recv(packet, remote_peer, local_primary_port);
    let (header, payload) = packet.parse()?;

    let target_cid = header.target_cid.get();
    let mut proxy_cid_info = None;
    // if proxying is involved, then the target_cid != 0
    if target_cid != 0 {
        // since target cid is not zero, there are two possibilities:
        // either [A] we are at the hLAN server, in which case the this_implicated_cid != target_cid
        // or, [B] we are at the destination, in which case implicated_cid == target_cid. If this is true, do normal processing
        // NOTE: When proxying DO NOT change the original implicated_CID in the header.
        // [*] in the case of proxying, it should only be done after a connection is well established
        // This would imply that the implicated cid is established in the HdpSession. As such, if the implicated CID is None,
        // then simply let normal logic below continue
        if let Some(this_implicated_cid) = this_implicated_cid {
            // this implies there is at least a connection between hLAN client and hLAN server, but we don't know which is which
            if this_implicated_cid != target_cid {
                // since the implicated_cid is not equal to the target_cid, it means we need to proxy to the target
                let _source_implicated_cid = header.session_cid.get();
                log::info!("Proxying packet from {} to {}", this_implicated_cid, target_cid);
                // Proxy will only occur if there exists a virtual connection, in which case, we get the TcpSender (since these are primary packets)
                let sess = inner!(session);
                let state_container = inner!(sess.state_container);
                if let Some(peer_vconn) = state_container.active_virtual_connections.get(&target_cid) {
                    // into_packet is a cheap operation the freezes the internal packet; we attain zero-copy through proxying here
                    if let Err(_err) = peer_vconn.sender.as_ref().unwrap().1.send(packet.into_packet()) {
                        log::error!("Proxy TrySendError to {}", target_cid);
                    }
                } else {
                    log::error!("Unable to proxy; virtual connection to {} is not alive", target_cid);
                }

                return PrimaryProcessorResult::Void
            } else {
                // since implicated_cid == target_cid, and target_cid != 0, we are at the destination
                // and need to use the endpoint crypto in order to process the packets
                proxy_cid_info = Some((header.session_cid.get(), target_cid))
            }
        }
    }

    let cmd_aux = header.cmd_aux;

    match header.cmd_primary {
        packet_flags::cmd::primary::DO_REGISTER => {
            super::register_packet::process(session, &header, payload, remote_peer)
        }

        packet_flags::cmd::primary::DO_CONNECT => {
            super::connect_packet::process(session, packet)
        }

        packet_flags::cmd::primary::KEEP_ALIVE => {
            super::keep_alive_packet::process(session, packet)
        }

        packet_flags::cmd::primary::GROUP_PACKET => {
            super::primary_group_packet::process(session, cmd_aux, packet, proxy_cid_info)
        }

        packet_flags::cmd::primary::DO_DISCONNECT => {
            super::disconnect_packet::process(session, &header, payload)
        }

        packet_flags::cmd::primary::DO_DRILL_UPDATE => {
            super::drill_update_packet::process(session, &header, payload)
        }

        packet_flags::cmd::primary::DO_DEREGISTER =>  {
            super::deregister_packet::process(session, &header, payload)
        }

        packet_flags::cmd::primary::DO_PRE_CONNECT => {
            super::preconnect_packet::process(session, &header, payload)
        }

        packet_flags::cmd::primary::PEER_CMD => {
            super::peer_cmd_packet::process(session, cmd_aux, packet)
        }

        packet_flags::cmd::primary::FILE => {
            super::file_packet::process(session, packet, proxy_cid_info)
        }

        _ => {
            warn!("The primary port received an invalid packet command. Dropping");
            PrimaryProcessorResult::Void
        }
    }
}