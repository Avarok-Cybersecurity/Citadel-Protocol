/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use hyxe_util::HyxeError;

/// Every node MUST have one of these. They map network id's (which are present on all packets to provide direction)
/// with IP addresses. Any listed NID is implied to be [mutually trusted] with the local node. Note, the NID != the CID. While
/// there may be multiple CIDs on a single client, there is only one NID per node. Every packet has a destination NID; this
/// implies the local client must have a list of A) trusted NIDs adjacent to the central mainframe server (either HyperLAN clients
/// and/or HyperWAN Servers) and B) trusted NIDs adjacent to all trusted HyperWAN servers. Since each CID on a local client
/// may have different trusted locations, then we can refine the conditions above: Each HyxeClient needs to have a single
/// TrustedNetworkMap per CID, while each HyxeServer needs to have a single TrustedNetworkMap per trusted HyperWAN server.
///
/// This allows the HyxeClients to only have the maps they need, thus saving space, while the HyxeServer takes the burden
/// of having ALL NIDs possible. As such: the server must process [NETWORK_MAP_SYNC] requests.
///
/// Restrictions: [A] A CID is required for all queries to a TrustedNetworkMap. [B] The TrustedNetworkMap cannot account
/// for the connection status of the NID (this is the job of the BridgeHandler)
///
/// Problem from this logic and packet header config: If a HyperWAN client receives a packet from an external HyperWAN
/// client, it will have the initial_cid in the header as the "sender" but no NID. Thus, the CID must be mapped to a NID. Perhaps,
/// then, the hop BEFORE a packet reaches the final destination (e.g., from HyperWAN server to interior HyperLAN client, or
/// from HyperLAN server to interior HyperLAN client), the last 8 bytes of the header which contains the NID can be changed
/// with the NID that corresponds to the initial sender.
///
/// Thought experiment to verify/adjust logic:
///
/// Packet is dispatched from the initial client, J, with intiial_cid iCID and destination_nid dNID. The packet will always go to
/// the central server regardless. Central server then looks at the packet's iCID to see if dNID is a mutually agreed
/// connection within `mutual_agreement_map` (if the server is synced with the client, then it should already be. If not (check `map_version`),
/// then the server should send a [NETWORK_MAP_SYNC] signal followed by the serialized object [ClientNetworkMap] through
/// the network back to J). Upon verification of mutual connection, the central server then determines if that CID
/// belongs somewhere in the HyperLAN or the HyperWAN. [Case A] If the CID is in the HyperLAN, then the server (being the last node
/// in the hop-series) changes the dNID to the original sender's NID. The server then pushes information into the session
/// bridge-handler which corresponds with the IP address of the ORIGINAL dNID (not the changed one). Note: the session must exist, or the
/// original sender will receive a [PEER_NOT_CONNECTED] signal. NEXT, in the case that the CID is in the HyperWAN:
///
/// [Case B] The initial client, J, with intiial_cid iCID and external destination_nid dNID, is dispatched from J to the central
/// mainframe server. Upon arrival, the server checks the iCID for the existence of iNID within its respective [ClientNetworkMap].
/// As with case [A], a [NETWORK_MAP_SYNC] signal may be needed to be sent to sync with the client in the case that `map_version` is
/// out-of-sync. If the version is in sync, yet, there is no connection, then iCID will receive a rebound [PEER_NOT_CONNECTED] packet.
/// If the versions are synced and the connection is valid [NOTE: IMPLEMENT NETWORK_MAP_SYNCER] then forward the packet to dNID's
/// central mainframe server. The packet is then parsed as usual and checked, and then the server checks to see if a session exists
/// between itself and
#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct ServerNetworkMap {
    /// NID of HyperWAN Server -> NID of HyperWAN Client ~> last registered IP addr.
    /// The HyperWAN Server must be in mutual agreement and have a unique network account
    /// with the adjacent HyperWAN Server.
    /// The SERVER owns this. The clients are not presented this value for sake of keeping
    /// the location of identity unknown. The client must have root-access into the HyxeServer's
    /// environment in order to discover the IP address associated with the NID they can read (which would void the warranty).
    pub ip_map: HashMap<u64, HashMap<u64, String>>,

    /// CID of HyperLAN Client Requesting data from the ip_map -> set of mutually
    /// agreed connections (NIDS). If NID does not exist, then the server should send
    /// an ERR_REQUIRES_REGISTRATION signal.
    ///
    /// This submap reinforces the idea "for all clients, independent of nid, there
    /// exists a unique ClientNetworkMap
    pub client_mutual_agreement_map: HashMap<u64, ClientNetworkMap>,
    pub local_nid: u64,
    pub map_version: u64,
}

#[derive(Serialize, Deserialize, Copy, Clone)]
impl ServerNetworkMap {
    pub fn new() -> Self {
        Self {
            ip_map: Default::default(),
            client_mutual_agreement_map: Default::default(),
            local_nid: 0,
            map_version: 0,
        }
    }

    /// This is useful for packets, as they have the initial_cid and destination_nid
    pub fn get_ip_by_nid(&self, cid_requesting: &u64, nid_requested: &u64) -> Option<String> {
        if let Some(client_network_map) = self.client_mutual_agreement_map.get(cid_requesting) {
            if let Some(node) = client_network_map.mutually_trusted_nodes.get(nid_requested) {
                let (respective_server_nid, respective_client_nid) = match node {
                    NodeData::HYPERLAN_SERVER(_) => {
                        (0, 4)
                    }

                    _ => { return None; }
                };
            }
        }
        None
    }

    pub fn get_nid_by_ip(&self, cid: u64, peer_addr: String) -> Option<u64> {}


    pub fn check_if_nid_exists(&self, cid_requesting: u64, nid_requested: u64) -> bool {}

    pub fn check_if_cid_belongs_to_nid(&self, cid: u64, nid: u64) -> bool {}

    pub fn get_version(&self) -> u64 {}

    pub fn get_local_nid(&self) -> u64 {}

    /// Data within the pre-existing local version should not just be wrecklessly replaced entirely
    /// by the new inbound map, because the inbound map, in the case of a ServerNetworkMap, has
    /// values relative to the sender and are thus relatively invalid for the receiver of the new
    /// map. Instead
    pub fn integrate_new(&mut self, updated_map: Self) -> Result<(), HyxeError> {}
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub enum NodeData {
    /// cid, cid "display name"
    HYPERLAN_SERVER(u64, String),
    HYPERLAN_CLIENT(u64, String),
    HYPERWAN_SERVER(u64, String),
    HYPERWAN_CLIENT(u64, String),
    SELF(u64, String),
}

/// This belongs to the CID which maps to this structure. The server should send this during the NETWORK_MAP_SYNC process
#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct ClientNetworkMap {
    /// nid ->
    pub mutually_trusted_nodes: HashMap<u64, (HashSet<NodeData>)>,
    pub relative_owning_cid: u64,
    pub containing_nid: u64,
    pub version: u64,
}

impl ClientNetworkMap {
    pub fn new(relative_owning_cid: u64, containing_nid: u64) -> Self {
        Self { mutually_trusted_nodes: HashMap::new(), relative_owning_cid, containing_nid, version: 0 }
    }
}