use std::net::IpAddr;
use crate::connection::stream_wrappers::old::RawInboundItem;
use crate::connection::server::Server;
use crate::connection::network_map::{NetworkMap, ClientViewport, NetworkSyncMap};
use crate::packet::definitions::PREFER_IPV6;
use hyxe_netdata::packet::StageDriverPacket;
use std::convert::TryFrom;
use crate::packet::misc::ConnectError;
use hyxe_crypt::drill_impls::DrillType;
use hyxe_crypt::prelude::Drill;
use hyxe_user::prelude::{NetworkAccount, HyperNodeAccountInformation};
use hyxe_user::client_account::ClientNetworkAccount;
use std::collections::HashMap;

/// The starting point in a network. N=0 hops. This is only existent for purposes of abstraction,
/// and does not actually ever exist as an actual state within the packet header
pub const SELF: u8 = 0;

/// Aka the "central server". N=1 hops
pub const HYPERLAN_SERVER: u8 = 1;

/// A client within reach of the HyperLAN server. N=2 hops
pub const HYPERLAN_CLIENT: u8 = 2;

/// Like a HyperLAN server, but existent in an outside network. N=2 hops
pub const HYPERWAN_SERVER: u8 = 3;

/// Like a HyperLAN client, but existent in an outside network. N=3 hops
pub const HYPERWAN_CLIENT: u8 = 4;

/// This provides the means for packet transformation about center-point nodes
pub mod translations;

/// The packet directionality structure is used to hold very important values which imply the future actions
/// of the juxtaposed packet.
#[derive(Clone)]
#[repr(C)]
pub struct PacketDirectionality {
    /// This is the state of the packet right before transmitting to the next node
    pub current_packet_hop_state: u8,
    /// This is the state of the packet expected to exist once it reaches the next node. It is relative to
    /// the current_packet_hop_state. This should be used to verify, upon packet-arrival, if the data is
    /// making its way around the network as expected.
    pub next_hop_state: u8,
    /// This is the endpoint type of the packet
    pub endpoint_destination_type: u8
}

/// This contains the past, present, and future of the packet's network trajectory. As such, it also contains
/// the endpoint cid + nid pair (possibly nid. The NID is only known by the endpoint's central server. The endpoint
/// NID is only initially imprinted upon a packet if the transmission-type is interserver. Even in client -> HyperLAN
/// client routes, the central server reserves mapping from the NID to CID. This implied that it is necessary that there
/// be no contradictions in CIDs from the perspective of the sending client).
#[derive(Clone)]
#[repr(C)]
pub struct PacketRoute {
    /// This is for determining the network node destination. However, multiple clients may exist at a single node,
    /// and as such, the destination nid alone is not enough to determine "who" gets the packet, because multiple
    /// clients may exist about a singular NID
    pub route_dest_nid: u64,
    /// This determines the "who" about a certain network node. Multiple clients may exist at a single node depending
    /// on the number of concurrent connections to different central servers
    pub route_dest_cid: u64,
    /// The original cid of this packet. Unlike above wherein the endpoint required both a CID and NID, the starting point
    /// does not need a NID since the CID -> NID -> IP mapping is saved on a central server. In other words, in a properly
    /// laid-out network, the endpoint only needs the CID in order to know who sent the data as well as the capacity to
    /// send data outbound. [When crafting a rebound packet], the `route_dest_nid` should be set to 0 thatway the central
    /// server can replace the zero with the correct NID value
    pub cid_original: u64,
    /// The original nid of this packet; the sending nid, in other words
    pub nid_original: u64,
    /// The network map version for which this data is valid (when a client connects, reconnects, registers, etc, the map will
    /// have to refresh)
    pub network_map_version: u32,
    /// The number of hops remaining,
    pub hops_remaining: u8,
    /// Where to send the information NEXT. This is used for sending data directly outbound. This may be IPv4 or IPv6 (preferable)
    pub next_ip: IpAddr,
    /// The directionality is for assisting the router to determine where to send data next. The router must keep into
    /// consideration the `route_dest_nid` and `route_dest_cid` above.
    pub directionality: PacketDirectionality
}

unsafe impl Send for PacketRoute {}
unsafe impl Sync for PacketRoute {}

/// Many times, the [PacketRoute] between two nodes is constant. For example, a no-response oneshot signal between a HyperLAN Client
/// and its HyperLAN Server depends upon a singular constant [PacketRoute]; the same can be said for a pro-response oneshot signal.
/// This is also true in reverse: a no-response oneshot signal between a HyperLAN Server and a HyperLAN Client, as well as the
/// pro-response version thereof. This is also true between two HyperLAN Clients, but with one additional hop being the central server.
/// Furthermore, these cases are also true between an interserver connection. Finally, this is all true for a HyperLAN to HyperWAN Client
/// connection. As such, for purposes of optimization at the cost of a negligible amount of RAM, we can pre-create these [PacketRoute]'s
/// for each scenario and for each owning [BridgeHandler]. This will save countless memsets and memcpy's, as all we have to do is pass
/// around a [&PacketRoute]. For multithreaded access, we need to implement [Send] and [Sync] for [PacketRoute].
///
/// A [PacketRouteStore] should be generated upon client connection. Importantly, when crafting packet that use the store, there is an
/// issue with the fact that `network_map_version` may be out of sync with the latest version. As such, this must be STRICTLY generated
/// upon client connection, and never serialized for later re-use.
pub struct PacketRouteStore {
    /// The key is either a CID or NID. Typically the key is a CID for an adjacent client, or a NID if the adjacent node is a server
    store: HashMap<u64, PacketRouteSubstore>
}

#[repr(C)]
struct PacketRouteSubstore {
    /// Expects a response
    exp: PacketRoute,
    /// Does not expect a response
    no_exp: PacketRoute
}

impl PacketRouteStore {
    /// Creates a new [PacketRoute]
    pub fn new() -> Self {
        Self { store: HashMap::new() }
    }

    /// The ID can be either a CID or NID
    pub fn get_route(&self, id: u64, expects_response: bool) -> Option<&PacketRoute> {
        if expects_response {
            Some(&self.store.get(&id)?.exp)
        } else {
            Some(&self.store.get(&id)?.no_exp)
        }
    }

    /// Adds a route to the store. This returns Ok(()) if no previous entry existed, otherwise, returns
    /// Err(())
    pub fn add_route(&mut self, id: u64, exp: PacketRoute, no_exp: PacketRoute) -> Result<(), ConnectError> {
        if !self.store.contains_key(&id) {
            debug_assert!(self.store.insert(id, PacketRouteSubstore { exp, no_exp }).is_none());
            Ok(())
        } else {
            Err(ConnectError::RouteExists)
        }
    }
}

impl PacketRoute {
    /// This is meant for the packet generation stage. This should NOT be called during the forwarding procedure.
    /// This performs a lookup of `dest_nid` and `dest_cid` in the `sender_viewport`.
    ///
    /// Some important notes: The `route_dest_nid` in the generated [PacketDirectionality] should be initially ZERO when
    /// sending from client to client, regardless of whether or not that client is on the HyperWAN or not (this information
    /// is to be invisible to clients; instead, the central servers have this information). The only NID that should be known
    /// for client -> client transmission is the central server. By lending this value to clients, this allows O(1) lookup
    /// times when needing to perform a client -> HyperWAN client route about the servers. IF, however, the transmission
    /// happens to be a client -> HyperLAN client route, then the `central_server_nid_of_dest_cid` should == `sender_viewport.nid_parent`
    pub fn new_client_to_client(local_cid: u64, local_nid: u64, dest_cid: u64, network_map: &NetworkMap) -> Option<Self> {
        let read = network_map.read();
        let (endpoint_destination_type, _, _) = *read.get_peer_location(dest_cid)?;
        let next_ip = *read.get_central_server_ip();
        let network_map_version = read.get_version();

        let directionality = PacketDirectionality {
            current_packet_hop_state: SELF,
            next_hop_state: HYPERLAN_SERVER, // When going from client to client, regardless if client -> HyperLAN/WAN, the next hop is the sending client's central server
            endpoint_destination_type  // This tells us what type of client we are sending information to
        };

        let hops_remaining = match endpoint_destination_type {
            HYPERLAN_CLIENT => 2,
            HYPERWAN_CLIENT => 3,
            _ => panic!("Invalid relative peer type")
        };

        Some(Self {
            route_dest_nid: 0, // set to zero initially. Once the juxtaposed packet makes its way to the LAST central server, this value will be changed accordingly
            route_dest_cid: dest_cid,
            cid_original: local_cid,
            nid_original: local_nid,
            network_map_version,
            hops_remaining,
            next_ip,
            directionality
        })
    }

    /// This is for sending data from a central server to a client. The server may request a response from the client, in which case,
    /// `expects_response` must be equal to `true`.
    pub fn new_hyperlan_server_to_hyperlan_client(local_nid: u64, dest_cid: u64, expects_response: bool, network_map_local: &NetworkMap) -> Option<Self> {
        let read = network_map_local.read();

        let client_info_ref = read.get_hyperlan_client(dest_cid)?;
        let client_nid = read.get_nid_from_cid(dest_cid)?;
        let next_ip = *read.get_hyperlan_client_ip(dest_cid)?;
        let network_map_version = read.get_version();

        let (endpoint_destination_type, hops_remaining) = {
            if expects_response {
                (HYPERLAN_SERVER, 2)
            } else {
                (HYPERLAN_CLIENT, 1)
            }
        };


        let directionality = PacketDirectionality {
            current_packet_hop_state: HYPERLAN_SERVER,
            next_hop_state: HYPERLAN_CLIENT,
            endpoint_destination_type
        };

        Some(Self {
            route_dest_nid: client_nid,
            route_dest_cid: dest_cid,
            cid_original: 0, // 0 => N/A => Sent from HyperLAN server thus irrelevant (no iCID either, as no HyperWAN Server is involved)
            nid_original: local_nid,
            network_map_version,
            hops_remaining,
            next_ip,
            directionality
        })
    }

    /// This is the inverse of `hyperlan_server_to_hyperlan_client`. For the unique case of
    pub fn new_hyperlan_client_to_hyperlan_server(local_cid: u64, dest_server_nid: u64, expects_response: bool, network_map_local: &NetworkMap) -> Option<Self> {
        let read = network_map_local.read();
        let local_nid = read.get_local_nid();
        let next_ip = *read.get_central_server_ip();
        let network_map_version = read.get_version();

        let (endpoint_destination_type, hops_remaining) = {
            if expects_response {
                (HYPERLAN_CLIENT, 2)
            } else {
                (HYPERLAN_SERVER, 1)
            }
        };

        let directionality = PacketDirectionality {
            current_packet_hop_state: HYPERLAN_CLIENT,
            next_hop_state: HYPERLAN_SERVER,
            endpoint_destination_type
        };

        Some(Self {
            route_dest_nid: dest_server_nid,
            route_dest_cid: 0, // The HyperLAN Server has no CID (no iCID either, as no HyperWAN Server is involved)
            cid_original: local_cid,
            nid_original: local_nid,
            network_map_version,
            hops_remaining,
            next_ip,
            directionality
        })
    }

    /// Sometimes, a client must communicate with an exterior HyperWAN Server. Although this process is necessarily mediated
    /// by the HyperLAN Server, a [PacketRoute] must show intention. Most [PacketRoute]'s that are outbound to the HyperWAN are
    /// going to be of type HyperLAN Client -> HyperWAN Client, thus, the question is raised: for what purpose does a route of
    /// type HyperLAN Client -> HyperWAN Server provide?
    ///     [1] Targeted broadcasts: For example, a client wants to advertise to all possible clients for when clients later
    ///     connect. Consider this as the "projected baker's stand"
    ///     [2] Registration purposes
    pub fn new_hyperlan_client_to_hyperwan_server(local_nid: u64, local_cid: u64, interserver_cid: u64, network_map_local: &NetworkMap) -> Option<Self> {
        let read = network_map_local.read();
        let network_map_version = read.get_version();

        let (_, central_server_nid, _) = *read.get_peer_location(interserver_cid)?;
        let next_ip = *read.get_central_server_ip();

        let directionality = PacketDirectionality {
            current_packet_hop_state: HYPERLAN_CLIENT,
            next_hop_state: HYPERLAN_SERVER,
            endpoint_destination_type: HYPERWAN_SERVER // Here, the common rule of properly formatting the full intention with expects_response in mind is not
                // honored. However, honoring this is not necessary, as expects_response is formatted in its own field independent of the directionality fields.
                // As such, we set the endpoint with confidence that the packet will be rebounded if necessary. Otherwise, in the case of a oneshot signal, the
                // directionality listed here is precise
        };

        Some(Self {
            route_dest_nid: central_server_nid,
            route_dest_cid: interserver_cid,
            cid_original: local_cid,
            nid_original: local_nid,
            network_map_version,
            hops_remaining: 2,
            next_ip,
            directionality
        })
    }

    /// This is the topological inverse of `new_hyperlan_client_to_hyperwan_server` above. As such, it provides the inverse means of achieving [1] and [2]
    pub fn new_hyperlan_server_to_hyperwan_client(local_nid: u64, dest_cid: u64, network_map_local: &NetworkMap) -> Option<Self> {
        let read = network_map_local.read();
        let network_map_version = read.get_version();

        let (_, central_server_nid, interserver_cid) = *read.get_peer_location(dest_cid)?; // We get the NID from the cid
        let next_ip = *read.get_hyperwan_server_ip(central_server_nid)?; // We then get the Ip from the NID, as desired

        let directionality = PacketDirectionality {
            current_packet_hop_state: HYPERLAN_SERVER,
            next_hop_state: HYPERWAN_SERVER,
            endpoint_destination_type: HYPERWAN_CLIENT
        };

        Some(Self {
            route_dest_nid: 0, // We keep this as zero per rules of the network (i.e., @ last hop, the appropriate central server replaces it with real nid)
            route_dest_cid: dest_cid,
            cid_original: interserver_cid, // There is no CID associated
            nid_original: local_nid,
            network_map_version,
            hops_remaining: 2,
            next_ip,
            directionality
        })

    }

    /// This is for the unique case of sending data between server to server. The rule that "the `route_dest_nid` == 0" does
    /// NOT apply here. Since the destination of a packet is a remote HyperWAN server, it is necessarily implied that the
    /// NID be known by other constraints in the system. In particular, the constraint that a central server, for all adjacent
    /// connections, must know the NID to that adjacent connection. Since a remote server is a subset of "all adjacent connections",
    /// then it is implied that a remote server's NID is known by the local central server.
    ///
    /// `expects_response`: If you expect a response from the adjacent HyperWAN server, supply `true`
    pub fn new_interserver(local_nid: u64, dest_server_nid: u64, expects_response: bool, network_map_local: &NetworkMap) -> Option<Self> {
        let next_ip = *network_map.read().get_hyperwan_server_ip(dest_server_nid)?;

        let endpoint_destination_type = {
            if expects_response {
                HYPERLAN_SERVER
            } else {
                HYPERWAN_SERVER
            }
        };

        let hops_remaining = 1;

        let directionality = PacketDirectionality {
            current_packet_hop_state: HYPERLAN_SERVER, // start at the server
            next_hop_state: HYPERWAN_SERVER, //
            endpoint_destination_type
        };

        Some(Self {
            route_dest_nid: dest_server_nid,
            route_dest_cid: 0, // There is no CID associated with a server of any type (whether that type is a HyperLAN/WAN server)
            cid_original: local_nid, // ***This is technically a hack***: This is an exception in the sense that we set the cid_original to the local server's NID, which is contradictory to the field name
            nid_original: local_nid,
            network_map_version: network_map.get_version(),
            hops_remaining,
            next_ip,
            directionality
        })
    }

    /// This prepares a [PacketRoute] that describes the packet's return trajectory back to its sender.
    ///
    /// The packet's route header information is NOT to be altered before this subroutine call
    pub fn prepare_rebound_route(packet: &StageDriverPacket) -> Self {
        let header = packet.get_header();
        let next_ip = packet.get_sender().ip();

        let nid_original = header.nid_original.get();

        let directionality = PacketDirectionality {
            current_packet_hop_state: header.next_hop_state,
            next_hop_state: header.current_packet_hop_state,
            endpoint_destination_type: header.endpoint_destination_type // it is up to the original sender to ensure that the endpoint type implies a rebound
        };

        let hops_remaining = Self::compute_hop_len(directionality.current_packet_hop_state, directionality.endpoint_destination_type);

        Self {
            route_dest_nid: nid_original, // it is the responsibility for the sender to appropriately set the values in the header as self
            route_dest_cid: header.route_dest_cid.get(),
            cid_original: header.cid_original.get(),
            nid_original,
            network_map_version: header.network_map_version.get(),
            hops_remaining,
            next_ip,
            directionality
        }
    }

    /// This computes the number of hops needed to go from the current state to the end state
    pub fn compute_hop_len(current_packet_hop_state: u8, endpoint_destination_type: u8) -> u8 {
        match current_packet_hop_state {
            HYPERLAN_CLIENT => {
                match endpoint_destination_type {
                    HYPERLAN_CLIENT => {
                        2
                    },

                    HYPERLAN_SERVER => {
                        1
                    },

                    HYPERWAN_SERVER => {
                        2
                    },

                    HYPERWAN_CLIENT => {
                        3
                    },

                    _ => {
                        panic!("Invalid specifier")
                    }
                }
            },

            HYPERLAN_SERVER => {
                match endpoint_destination_type {
                    HYPERLAN_CLIENT => {
                        1
                    },

                    HYPERLAN_SERVER => {
                        panic!("Distance from self to self is invalid. Use HyperLAN server to HyperWAN server instead")
                    },

                    HYPERWAN_SERVER => {
                        1
                    },

                    HYPERWAN_CLIENT => {
                        2
                    },

                    _ => {
                        panic!("Invalid specifier")
                    }
                }
            },

            HYPERWAN_SERVER => {
                match endpoint_destination_type {
                    HYPERLAN_CLIENT => {
                        2
                    },

                    HYPERLAN_SERVER => {
                        1
                    },

                    HYPERWAN_SERVER => {
                        1
                    },

                    HYPERWAN_CLIENT => {
                        1
                    },

                    _ => {
                        panic!("Invalid specifier")
                    }
                }
            },

            HYPERWAN_CLIENT => {
                match endpoint_destination_type {
                    HYPERLAN_CLIENT => {
                        3
                    },

                    HYPERLAN_SERVER => {
                        2
                    },

                    HYPERWAN_SERVER => {
                        1
                    },

                    HYPERWAN_CLIENT => {
                        2
                    },

                    _ => {
                        panic!("Invalid specifier")
                    }
                }
            }
            _ => {
                panic!("Invalid specifier")
            }
        }
    }

    /// Determines if the node type is in the HyperWAN or HyperLAN
    #[inline]
    pub fn peer_is_hyperlan(peer_point: u8) -> bool {
        peer_point == HYPERLAN_SERVER || peer_point == HYPERLAN_CLIENT
    }

    /// Applies ALL the fields within this [PacketRoute] to the `packet`. This will overwrite the header with
    /// the contained fields of self
    pub fn apply(&self, mut packet: &mut StageDriverPacket) {
        let header = packet.get_mut_header();
        header.route_dest_nid.set(self.route_dest_nid);
        header.route_dest_cid.set(self.route_dest_cid);
        header.cid_original.set(self.route_dest_cid);
        header.hops_remaining = self.hops_remaining;
        header.network_map_version.set(self.network_map_version);

        header.current_packet_hop_state = self.directionality.current_packet_hop_state;
        header.next_hop_state = self.directionality.next_hop_state;
        header.endpoint_destination_type = self.directionality.endpoint_destination_type;
    }

}