use crate::hdp::packet_processor::PrimaryProcessorResult;
use crate::error::NetworkError;
use crate::prelude::{PeerResponse, PeerSignal, Ticket, PeerConnectionType};
use crate::hdp::packet_processor::peer::peer_cmd_packet::route_signal_response;
use crate::hdp::hdp_session::HdpSession;
use hyxe_crypt::hyper_ratchet::HyperRatchet;
use hyxe_crypt::drill::SecurityLevel;
use crate::hdp::peer::peer_layer::{Username, HyperNodePeerLayerInner};

#[cfg_attr(feature = "localhost-testing", tracing::instrument(target = "lusna", skip_all, ret, err, fields(is_server = session.is_server, implicated_cid = implicated_cid, target_cid = target_cid)))]
pub async fn handle_response_phase_post_register(peer_layer: &mut HyperNodePeerLayerInner, peer_conn_type: PeerConnectionType, username: Username, peer_response: PeerResponse, ticket: Ticket, implicated_cid: u64, target_cid: u64, timestamp: i64, session: &HdpSession, sess_hyper_ratchet: &HyperRatchet, security_level: SecurityLevel) -> Result<PrimaryProcessorResult, NetworkError> {
    let decline = match &peer_response { PeerResponse::Decline => true, _ => false };

    route_signal_response(PeerSignal::PostRegister(peer_conn_type, username, None,Some(ticket), Some(peer_response)), implicated_cid, target_cid, timestamp, ticket, peer_layer, session.clone(), &sess_hyper_ratchet,
                          |this_sess, _peer_sess, _original_tracked_posting| {
                              if !decline {
                                  let account_manager = this_sess.account_manager.clone();
                                  let task = async move {
                                      if let Err(err) = account_manager.register_hyperlan_p2p_as_server(implicated_cid, target_cid).await {
                                          // TODO: route error
                                          log::error!(target: "lusna", "Unable to register hyperlan p2p at server: {:?}", err);
                                      }
                                  };

                                  let _ = tokio::task::spawn(task);
                              }
                          }, security_level).await
}