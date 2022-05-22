use crate::hdp::hdp_packet_processor::PrimaryProcessorResult;
use crate::error::NetworkError;
use crate::prelude::{PeerResponse, PeerSignal, Ticket, FcmPostRegister, PeerConnectionType};
use crate::hdp::hdp_packet_processor::peer::peer_cmd_packet::route_signal_response;
use crate::hdp::hdp_session::HdpSession;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_crypt::drill::SecurityLevel;
use crate::hdp::peer::peer_layer::{Username, HyperNodePeerLayerInner};

pub async fn handle_response_phase(peer_layer: &mut HyperNodePeerLayerInner, peer_conn_type: PeerConnectionType, username: Username, peer_response: PeerResponse, ticket: Ticket, fcm: FcmPostRegister, implicated_cid: u64, target_cid: u64, timestamp: i64, session: &HdpSession, sess_hyper_ratchet: &HyperRatchet, security_level: SecurityLevel) -> Result<PrimaryProcessorResult, NetworkError> {
    let decline = match &peer_response { PeerResponse::Decline => true, _ => false };

    route_signal_response(PeerSignal::PostRegister(peer_conn_type, username, None,Some(ticket), Some(peer_response), fcm), implicated_cid, target_cid, timestamp, ticket, peer_layer, session.clone(), &sess_hyper_ratchet,
                          |this_sess, _peer_sess, _original_tracked_posting| {
                              if !decline {
                                  let account_manager = this_sess.account_manager.clone();
                                  let task = async move {
                                      if let Err(err) = account_manager.register_hyperlan_p2p_as_server(implicated_cid, target_cid).await {
                                          // TODO: route error
                                          log::error!("Unable to register hyperlan p2p at server: {:?}", err);
                                      }
                                  };

                                  let _ = tokio::task::spawn(task);
                              }
                          }, security_level).await
}