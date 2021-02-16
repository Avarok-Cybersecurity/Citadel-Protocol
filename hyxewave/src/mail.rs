use hyxe_net::hdp::peer::peer_layer::{PeerSignal, PeerResponse, PeerConnectionType, Username};
use std::collections::HashMap;
use hyxe_net::hdp::hdp_server::Ticket;
use std::fmt::{Display, Formatter};
use tokio::time::Instant;
use hyxe_net::hdp::peer::message_group::MessageGroupKey;
use hyxe_crypt::drill::SecurityLevel;
use serde::{Serialize, Deserialize};
use hyxe_net::fcm::kem::FcmPostRegister;

#[derive(Default)]
pub struct ConsoleSessionMail {
    pub signal_mail: HashMap<usize, PeerSignal>,
    // used for reserving a unique index in the hashmaps
    pub unique_counter: usize,
    pub incoming_requests: HashMap<usize, IncomingPeerRequest>,
    pub incoming_group_requests: HashMap<usize, IncomingGroupRequest>
}

impl ConsoleSessionMail {
    pub fn new() -> Self {
        Self { unique_counter: 0, .. Default::default() }
    }

    pub fn get_signal_count(&self) -> usize {
        self.signal_mail.len()
    }

    pub fn visit_requests(&self, mut visitor: impl FnMut(usize, &IncomingPeerRequest)) {
        self.incoming_requests.iter().for_each(|(mail_id, val)| visitor(*mail_id, val))
    }

    pub fn visit_signals(&self, mut visitor: impl FnMut(usize, &PeerSignal)) {
        self.signal_mail.iter().for_each(|(mail_id, val)| visitor(*mail_id, val))
    }

    pub fn visit_group_requests(&self, mut visitor: impl FnMut(usize, &IncomingGroupRequest)) {
        self.incoming_group_requests.iter().for_each(|(mail_id, val)| visitor(*mail_id, val))
    }

    pub fn remove_signals_range(&mut self) -> Vec<PeerSignal> {
        self.signal_mail.drain().map(|res| res.1).collect::<Vec<PeerSignal>>()
    }

    pub fn remove_request(&mut self, mail_id: usize) -> Option<IncomingPeerRequest> {
        self.incoming_requests.remove(&mail_id)
    }

    pub fn remove_group_request(&mut self, mail_id: usize) -> Option<IncomingGroupRequest> {
        self.incoming_group_requests.remove(&mail_id)
    }

    /// Inserts the request and returns the mail ID associated with the newly placed item
    pub fn on_peer_request_received(&mut self, incoming: IncomingPeerRequest) -> usize {
        let next_ticket_id = self.get_and_increment_unique_id();
        self.incoming_requests.insert(next_ticket_id, incoming);
        next_ticket_id
    }

    /// Inserts the request and returns the mail ID associated with the newly placed item
    pub fn on_group_request_received(&mut self, implicated_local_cid: u64, ticket: Ticket, key: MessageGroupKey) -> usize {
        let next_ticket_id = self.get_and_increment_unique_id();
        let group_request = IncomingGroupRequest { implicated_local_cid, ticket, key };
        self.incoming_group_requests.insert(next_ticket_id, group_request);
        next_ticket_id
    }

    pub fn clear_mail(&mut self) {
        self.signal_mail.clear();
        self.incoming_requests.clear();
        self.unique_counter = 0;
    }

    fn get_and_increment_unique_id(&mut self) -> usize {
        let mail_id = self.unique_counter;
        self.unique_counter = mail_id.wrapping_add(1);
        mail_id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingGroupRequest {
    pub implicated_local_cid: u64,
    pub ticket: Ticket,
    pub key: MessageGroupKey
}

#[derive(Debug, Clone)]
pub enum IncomingPeerRequest {
    Connection(Ticket, PeerConnectionType, Instant, SecurityLevel),
    Register(Ticket, Username, PeerConnectionType, Instant, FcmPostRegister)
}

impl Display for IncomingPeerRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let val = match self {
            IncomingPeerRequest::Connection(..) => "Connection",
            IncomingPeerRequest::Register(..) => "Registration"
        };

        write!(f, "{}", val)
    }
}

impl IncomingPeerRequest {

    pub fn get_ticket_assert_register(&self) -> Option<Ticket> {
        match self {
            IncomingPeerRequest::Register(ticket, ..) => Some(ticket.clone()),
            _ => None
        }
    }

    pub fn get_ticket_assert_connect(&self) -> Option<Ticket> {
        match self {
            IncomingPeerRequest::Connection(ticket, ..) => Some(ticket.clone()),
            _ => None
        }
    }


    pub fn is_connect(&self) -> bool {
        match self {
            IncomingPeerRequest::Connection(..) => true,
            _ => false
        }
    }

    pub fn is_register(&self) -> bool {
        match self {
            IncomingPeerRequest::Register(..) => true,
            _ => false
        }
    }

    pub fn assert_register_get_username(&self) -> Option<String> {
        match self {
            IncomingPeerRequest::Register(_, username, ..) => Some(username.clone()),
            _ => None
        }
    }

    pub fn get_implicated_cid(&self) -> u64 {
        match self {
            IncomingPeerRequest::Register(_,_, conn, _, _) => {
                match conn {
                    PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, _target_cid) => *implicated_cid,
                    PeerConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, _icid, _target_cid) => *implicated_cid,
                }
            }

            IncomingPeerRequest::Connection(_, conn, ..) => {
                match conn {
                    PeerConnectionType::HyperLANPeerToHyperLANPeer(implicated_cid, _target_cid) => *implicated_cid,
                    PeerConnectionType::HyperLANPeerToHyperWANPeer(implicated_cid, _icid, _target_cid) => *implicated_cid,
                }
            }
        }
    }

    pub fn get_target_cid(&self) -> u64 {
        match self {
            IncomingPeerRequest::Register(_,_, conn, ..) => {
                match conn {
                    PeerConnectionType::HyperLANPeerToHyperLANPeer(_implicated_cid, target_cid) => *target_cid,
                    PeerConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, target_cid) => *target_cid,
                }
            }

            IncomingPeerRequest::Connection(_, conn, ..) => {
                match conn {
                    PeerConnectionType::HyperLANPeerToHyperLANPeer(_implicated_cid, target_cid) => *target_cid,
                    PeerConnectionType::HyperLANPeerToHyperWANPeer(_implicated_cid, _icid, target_cid) => *target_cid,
                }
            }
        }
    }

    /// Note: once you start to implement the HyperWAN system, ENSURE that the ICID is EQUIVALENT on BOTH ends!
    /// This really should be unique
    ///
    /// This FLIPS the ordering, as required
    pub fn prepare_response_assert_connection(self, response: PeerResponse) -> Option<PeerSignal> {
        match self {
            IncomingPeerRequest::Connection(ticket, peer_conn_type, _, endpoint_security_level) => {
                match peer_conn_type {
                    PeerConnectionType::HyperLANPeerToHyperLANPeer(original_cid, original_target) => {
                        Some(PeerSignal::PostConnect(PeerConnectionType::HyperLANPeerToHyperLANPeer(original_target, original_cid), Some(ticket), Some(response), endpoint_security_level))
                    }

                    PeerConnectionType::HyperLANPeerToHyperWANPeer(original_cid, icid, original_target) => {
                        Some(PeerSignal::PostConnect(PeerConnectionType::HyperLANPeerToHyperWANPeer(original_target, icid, original_cid), Some(ticket), Some(response), endpoint_security_level))
                    }
                }
            }

            _ => None
        }
    }

    pub fn prepare_response_assert_register(self, response: PeerResponse, username: String) -> Option<PeerSignal> {
        match self {
            IncomingPeerRequest::Register(ticket,_old_username, peer_conn_type, _, fcm) => {
                match peer_conn_type {
                    PeerConnectionType::HyperLANPeerToHyperLANPeer(original_cid, original_target) => {
                        Some(PeerSignal::PostRegister(PeerConnectionType::HyperLANPeerToHyperLANPeer(original_target, original_cid), username, Some(ticket), Some(response), fcm))
                    }

                    PeerConnectionType::HyperLANPeerToHyperWANPeer(original_cid, icid, original_target) => {
                        Some(PeerSignal::PostRegister(PeerConnectionType::HyperLANPeerToHyperWANPeer(original_target, icid, original_cid), username, Some(ticket), Some(response), fcm))
                    }
                }
            }

            _ => None
        }
    }
}