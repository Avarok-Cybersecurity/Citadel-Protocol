use bytes::BytesMut;

use crate::hdp::hdp_packet_processor::peer::peer_cmd_packet;

use super::includes::*;
use crate::error::NetworkError;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc::UnboundedSender;
use std::pin::Pin;
use futures::Future;
use crate::macros::ContextRequirements;

pub trait ProcessorFuture: Future<Output=Result<PrimaryProcessorResult, NetworkError>> + ContextRequirements {}
impl<T: Future<Output=Result<PrimaryProcessorResult, NetworkError>> + ContextRequirements> ProcessorFuture for T {}

pub type ConcurrentProcessorTx = UnboundedSender<Pin<Box<dyn ProcessorFuture>>>;

/// For primary-port packet types. NOT for wave ports
pub fn process(this_implicated_cid: Option<u64>, session: &HdpSession, remote_peer: SocketAddr, local_primary_port: u16, packet: BytesMut, concurrent_processor_tx: &ConcurrentProcessorTx) -> Result<PrimaryProcessorResult, NetworkError> {
    //return_if_none!(header_obfuscator.on_packet_received(&mut packet));

    let packet = HdpPacket::new_recv(packet, remote_peer, local_primary_port);
    let (header, _payload) = return_if_none!(packet.parse(), "Unable to parse packet");
    //log::info!("RECV Raw packet: {:?}", &*header);

    let target_cid = header.target_cid.get();
    let mut endpoint_cid_info = None;
    // if proxying/p2p is involved, then the target_cid != 0
    let cmd_primary = header.cmd_primary;
    let cmd_aux = header.cmd_aux;
    let header_drill_vers = header.drill_version.get();

    match check_proxy(this_implicated_cid, header.cmd_primary, header.cmd_aux, header.session_cid.get(), target_cid, session, &mut endpoint_cid_info, ReceivePortType::OrderedReliable, packet) {
        Some(packet) => {
            match cmd_primary {
                packet_flags::cmd::primary::DO_REGISTER => {
                    super::register_packet::process(session, packet, remote_peer, concurrent_processor_tx)
                }

                packet_flags::cmd::primary::DO_CONNECT => {
                    super::connect_packet::process(session, packet, concurrent_processor_tx)
                }

                packet_flags::cmd::primary::KEEP_ALIVE => {
                    super::keep_alive_packet::process(session, packet, concurrent_processor_tx)
                }

                packet_flags::cmd::primary::GROUP_PACKET => {
                    super::primary_group_packet::process(session, cmd_aux, packet, endpoint_cid_info)
                }

                packet_flags::cmd::primary::DO_DISCONNECT => {
                    super::disconnect_packet::process(session, packet)
                }

                packet_flags::cmd::primary::DO_DRILL_UPDATE => {
                    super::drill_update_packet::process(session, packet, header_drill_vers, endpoint_cid_info)
                }

                packet_flags::cmd::primary::DO_DEREGISTER =>  {
                    super::deregister_packet::process(session, packet, concurrent_processor_tx)
                }

                packet_flags::cmd::primary::DO_PRE_CONNECT => {
                    super::preconnect_packet::process(session, packet, concurrent_processor_tx)
                }

                packet_flags::cmd::primary::PEER_CMD => {
                    peer_cmd_packet::process(session, cmd_aux, packet, header_drill_vers, endpoint_cid_info, concurrent_processor_tx)
                }

                packet_flags::cmd::primary::FILE => {
                    super::file_packet::process(session, packet, endpoint_cid_info)
                }

                packet_flags::cmd::primary::HOLE_PUNCH => {
                    super::hole_punch::process(session, packet, header_drill_vers, endpoint_cid_info)
                }

                _ => {
                    warn!("The primary port received an invalid packet command. Dropping");
                    Ok(PrimaryProcessorResult::Void)
                }
            }
        }

        None => {
            Ok(PrimaryProcessorResult::Void)
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum ReceivePortType {
    OrderedReliable,
    UnorderedUnreliable
}

// returns None if the packet should finish being processed. Inlined for slightly faster TURN proxying
#[inline]
pub(crate) fn check_proxy(this_implicated_cid: Option<u64>, cmd_primary: u8, cmd_aux: u8, header_session_cid: u64, target_cid: u64, session: &HdpSession, endpoint_cid_info: &mut Option<(u64, u64)>, recv_port_type: ReceivePortType, packet: HdpPacket) -> Option<HdpPacket> {
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
                log::info!("Proxying {}:{} packet from {} to {}", cmd_primary, cmd_aux, this_implicated_cid, target_cid);
                // Proxy will only occur if there exists a virtual connection, in which case, we get the TcpSender (since these are primary packets)

                let mut state_container = inner_mut_state!(session.state_container);
                state_container.meta_expiry_state.on_event_confirmation();

                if let Some(peer_vconn) = state_container.active_virtual_connections.get(&target_cid) {
                    // Ensure that any p2p conn proxied packets (i.e., TURNed packets) can continue to traverse until any full disconnections occur
                    peer_vconn.last_delivered_message_timestamp.store(Some(Instant::now()), Ordering::SeqCst);
                    // into_packet is a cheap operation the freezes the internal packet; we attain zero-copy when proxying here
                    match recv_port_type {
                        ReceivePortType::OrderedReliable => {

                            #[cfg(all(feature = "localhost-testing", feature = "localhost-testing-assert-no-proxy"))]
                                {
                                    if cmd_primary == packet_flags::cmd::primary::GROUP_PACKET && cmd_aux == packet_flags::cmd::aux::group::GROUP_HEADER {
                                        log::error!("***Did not expect packet to be proxied via feature flag*** | local is server: {}", session.is_server);
                                        std::process::exit(1)
                                    }
                                }

                            if let Err(_err) = peer_vconn.sender.as_ref().unwrap().1.unbounded_send(packet.into_packet()) {
                                log::error!("Proxy TrySendError to {}", target_cid);
                            }
                        }

                        ReceivePortType::UnorderedUnreliable => {
                            if let Some(udp_sender) = peer_vconn.sender.as_ref().unwrap().0.as_ref() {
                                if let Err(_err) = udp_sender.unbounded_send(packet.into_packet()) {
                                    log::error!("Proxy TrySendError to {}", target_cid);
                                }
                            } else {
                                log::error!("UDP sender not yet loaded (proxy)");
                            }
                        }
                    }
                } else {
                    log::warn!("Unable to proxy; virtual connection to {} is not alive", target_cid);
                }

                return None;
            } else {
                // since implicated_cid == target_cid, and target_cid != 0, we are at the destination
                // and need to use the endpoint crypto in order to process the packets
                *endpoint_cid_info = Some((header_session_cid, target_cid))
            }
        }
    }

    Some(packet)
}