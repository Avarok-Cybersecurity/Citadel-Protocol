use crate::error::NetworkError;
use crate::prelude::{PeerConnectionType, PeerResponse, PeerSignal};
use crate::proto::packet_processor::includes::VirtualConnectionType;
use crate::proto::packet_processor::peer::peer_cmd_packet::route_signal_response;
use crate::proto::packet_processor::PrimaryProcessorResult;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use citadel_crypt::stacked_ratchet::StackedRatchet;
use citadel_types::crypto::SecurityLevel;
use citadel_types::proto::{SessionSecuritySettings, UdpMode};

#[cfg_attr(feature = "localhost-testing", tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err, fields(is_server = session.is_server, implicated_cid = implicated_cid, target_cid = target_cid)))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_response_phase_post_connect(
    peer_conn_type: PeerConnectionType,
    ticket: Ticket,
    peer_response: PeerResponse,
    endpoint_security_level: SessionSecuritySettings,
    udp_enabled: UdpMode,
    implicated_cid: u64,
    target_cid: u64,
    timestamp: i64,
    session: &CitadelSession,
    sess_hyper_ratchet: &StackedRatchet,
    security_level: SecurityLevel,
) -> Result<PrimaryProcessorResult, NetworkError> {
    // the signal is going to be routed from HyperLAN Client B to HyperLAN client A (response phase)
    route_signal_response(PeerSignal::PostConnect {
        peer_conn_type,
        ticket_opt: Some(ticket),
        invitee_response: Some(peer_response),
        session_security_settings: endpoint_security_level,
        udp_mode: udp_enabled,
        session_password: None,
    }, implicated_cid, target_cid, timestamp, ticket,session.clone(), sess_hyper_ratchet,
                          |this_sess, peer_sess, _original_tracked_posting| {
                              // when the route finishes, we need to update both sessions to allow high-level message-passing
                              // In other words, forge a virtual connection
                              // In order for routing of packets to be fast, we need to get the direct handles of the stream
                              // placed into the state_containers
                              if let Some(this_tcp_sender) = this_sess.to_primary_stream.clone() {
                                  if let Some(peer_tcp_sender) = peer_sess.to_primary_stream.clone() {
                                      let mut this_sess_state_container = inner_mut_state!(this_sess.state_container);
                                      let mut peer_sess_state_container = inner_mut_state!(peer_sess.state_container);

                                      // The UDP senders may not exist (e.g., TCP only mode)
                                      let this_udp_sender = this_sess_state_container.udp_primary_outbound_tx.clone();
                                      let peer_udp_sender = peer_sess_state_container.udp_primary_outbound_tx.clone();
                                      // rel to this local sess, the key = target_cid, then (implicated_cid, target_cid)
                                      let virtual_conn_relative_to_this = VirtualConnectionType::LocalGroupPeer {
                                          implicated_cid,
                                          peer_cid: target_cid
                                      };
                                      let virtual_conn_relative_to_peer = VirtualConnectionType::LocalGroupPeer {
                                          implicated_cid: target_cid,
                                          peer_cid: implicated_cid
                                      };
                                      this_sess_state_container.insert_new_virtual_connection_as_server(target_cid, virtual_conn_relative_to_this, peer_udp_sender, peer_tcp_sender);
                                      peer_sess_state_container.insert_new_virtual_connection_as_server(implicated_cid, virtual_conn_relative_to_peer, this_udp_sender, this_tcp_sender);
                                      log::trace!(target: "citadel", "Virtual connection between {} <-> {} forged", implicated_cid, target_cid);
                                      // TODO: Ensure that, upon disconnect, the corresponding entry gets dropped in the connection table of not the dropped peer
                                  }
                              }
                          }, security_level).await
}
