use crate::connection::connection::ConnectionHandle;
use hyxe_user::client_account::ClientNetworkAccount;
use hyxe_user::network_account::NetworkAccount;
use crate::packet::misc::ConnectError;
use futures::{Sink, AsyncSink, Async, Poll};
use crate::connection::stream_wrappers::old::{RawInboundItem, OutboundItem};
use std::net::IpAddr;
use crate::packet::packet_layout::{BaseHeaderConfig, determine_layout, PacketLayout0D, PacketLayout1D, PacketLayout2D};
use crate::misc::get_time;
use hyxe_crypt::drill::SecurityLevel;
use crate::routing::{PacketRoute, HYPERLAN_SERVER, HYPERLAN_CLIENT, HYPERWAN_SERVER, HYPERWAN_CLIENT, PacketRouteStore};
use hyxe_crypt::prelude::{DrillType, Drill};
use zerocopy::ByteSlice;
use std::pin::Pin;
use crate::packet::inbound::expectancy::{ExpectancyRequest, ExpectancyResponse};
use crate::packet::inbound::stage_driver::StageDriverHandle;
use crate::packet::definitions::{SINGLETON_EXPECTANCY_TIMEOUT, AVERAGE_WORLDWIDE_DOWNLOAD_RATE, PORT_START, DEFAULT_AUXILIARY_PORTS, PREFER_IPV6, PINNED_IP_MODE};
use hyxe_netdata::packet::StageDriverPacket;
use hyxe_user::hypernode_account::HyperNodeAccountInformation;
use crate::packet::outbound::packet_crafter::{craft_packet, craft_signal, craft_oneshot_signal};
use crate::packet::outbound::hyperlan::send_data::craft_send_data;
use futures::sync::mpsc::{UnboundedSender, Sender};
use crate::routing::translations::translate_packet_route_details;
use crate::connection::network_map::NetworkMap;
use hyxe_user::account_manager::AccountManager;
use std::ops::Try;

/// Whereas the sink_stage's in legacy_hyxe_net deal with inbound packet validity,
/// the BridgeHandler deals with outbound packet validity. The BridgeHandler
/// is a gate for any `Session`'s ability to send packets to a remote peer.
/// The BridgeHandler helps verify that a connection is current ontop of
/// whatever connection exists at the networking-protocol layer (e.g., TCP,
/// UDP, KCP, UDT).
///
/// Determines if the bridge is open or closed
pub enum BridgeState {
    /// When the bridge is open, data can freely enter and exit
    OPEN,
    /// When the bridge is closed, data cannot leave, but packets can be queued
    CLOSED
}

/// This is for client-based connections that need data sent to the adjacent end point
pub struct BridgeHandler<'cxn, 'session: 'cxn> {
    /// The handle to the underlying connection. This requires to be pinned to the heap to allows for memory location persistence
    pub handle: Pin<Box<ConnectionHandle<'cxn, 'session>>>,
    /// This should be None if in server mode for the lifetime of this structure. This should be some for a client connection. This
    /// should be Some for an interserver connection
    pub connection_client: Option<ClientNetworkAccount>,
    /// The adjacent node's networking information
    pub local_nac: NetworkAccount,
    network_map: NetworkMap,
    packet_route_store: PacketRouteStore,
    stage_driver_handle: StageDriverHandle<'cxn, 'session, 'session>,
    local_is_server: bool,
    state: BridgeState
}

impl<'cxn, 'session: 'cxn> BridgeHandler<'cxn, 'session> {
    /// Create a new Bridge from an already active ConnectionHandle
    /// `cnac`: This should be strictly `None` if this bridge is a loopback type (i.e., a server listener). If this is for a client or interserver connection, then `Some` must exist
    /// `local_is_server`: If this bridge was generated via tubing instead of requesting a connection like a normal client, this should be set to true. Servers will later-on have to
    /// update the routing information manually via `cxn_update_cnac`
    pub fn new(stage_driver_handle: StageDriverHandle, handle: Pin<Box<ConnectionHandle<'cxn, 'session>>>, cnac: Option<ClientNetworkAccount>, local_nac: &NetworkAccount, network_map: NetworkMap, local_is_server: bool) -> Self {
        let mut packet_route_store = PacketRouteStore::new();
        // Now, we need to add the default routes for sending data across the bridge: pure oneshots, and echo oneshots
        if !local_is_server {
            let network_map_version = network_map.read().get_version();
            let cnac = cnac.as_ref().unwrap();
            let local_nid = local_nac.get_id();

            let pure_signal = PacketRoute::prepare_oneshot(HYPERLAN_CLIENT, HYPERLAN_SERVER, local_nid, network_map_version, cnac, false);
            let echo_signal = PacketRoute::prepare_oneshot(HYPERLAN_CLIENT, HYPERLAN_SERVER, local_nid, network_map_version, cnac, true);

            assert!(packet_route_store.add_route(cnac.get_id(), echo_signal, pure_signal).is_ok());
        }

        Self { handle, stage_driver_handle, connection_client: cnac, local_nac: local_nac.clone(), network_map, packet_route_store, local_is_server, state: BridgeState::CLOSED }
    }

    /// Begins the underlying client connection by asynchronously executing the lower-level [ConnectionHandle] in stream-mode.
    ///
    /// This is intended for both client connections and interserver connections
    pub async fn start_connection(&mut self) -> Result<(), ConnectError> {
        debug_assert!(self.connection_client.is_some());
        unimplemented!()
    }

    /// Executes the lower-level handle's server function
    pub async fn start_server(&'session mut self, inbound_tx: &'session UnboundedSender<RawInboundItem>, new_tubing_sender: &'session UnboundedSender<(IpAddr, u16, UnboundedSender<OutboundItem>, Sender<u8>)>) -> Result<(), ConnectError> {
        debug_assert!(self.connection_client.is_none());
        self.handle.start_server(inbound_tx, new_tubing_sender).await
    }

    /// Calculates the [PacketRoute] relative to this node with consideration that the adjacent node will next receive the packet.
    /// This will panic under several circumstances as highlighted below, and, if the `connection_client` of self is `None`.
    /// After calculation, it adds the route to the internal store. This will return a bad route error if an improper configuration
    /// is detected
    ///
    /// `route_dest_cid`: Regardless of the local node type, this should always exist. A [ClientNetworkAccount] is necessary for
    /// both standard client connections AND interserver connections. By the rules of the [HyxeNetwork], a CID is always visible.
    /// Before calling this subroutine, it is expected that the CID exists, otherwise a panic will occur. Since a CID is present,
    /// and assuming there is NO `route_dest_nid`, these routes are possible:
    ///
    ///     [1] HyperLAN Client -> HyperLAN Server (1 hop), or;
    ///     [2] HyperLAN Client -> HyperLAN Client (2 hops), or;
    ///     [3] HyperLAN Client -> HyperWAN Server (2 hops), or;
    ///     [4] HyperLAN Client -> HyperWAN Client (3 hops)
    ///
    /// *Exception*: If the route type is from a HyperLAN Client to a HyperLAN Server, then the local HyperLAN client's CID should
    /// be used for the `route_dest_cid`.
    ///
    /// Other notes: `route_dest_cid` can also represent the interserver CID (iCID) in the case a packet's endpoint is a HyperWAN
    /// server
    ///
    /// `route_dest_nid`: This is needed only when the route destination is directly adjacent to a server type. If this value exists,
    /// then it necessarily* implies that the local node is a server, and, that the hop is directly adjacent to this node. The two
    /// examples are:
    ///
    ///     [5] The local node is a HyperLAN Server, and the hop destination is a HyperLAN Client (1 hop), or;
    ///     [6] The local node is a HyperLAN Server, and the hop destination is a HyperWAN Server (1 hop), or;
    ///     [7] The local node is a HyperLAN Server, and the hop destination is a HyperWAN Client (2 hops)
    ///
    /// *Exception*: The `route_dest_nid` is not known in the case that a route needs to be constructed between a HyperLAN Server and a
    /// HyperWAN Client. The reason being is another rule of the [HyxeNetwork] ... The rule is that the NID is ONLY KNOWN IF that NID
    /// belongs to a central server's HyperLAN. This helps protect the location of the node information. By keeping the NID a secret, a
    /// client cannot correlate any concurrent connections to a NID. If the `route_dest_nid` is  `None`, then 0 will be used in its place
    /// and it will be expected that the appropriate central server replaces it in the header with the correct NID upon arrival to the next
    /// hop
    pub fn add_packet_route(&mut self, route_dest_cid: u64, route_dest_nid: Option<u64>, account_manager: &AccountManager) -> Result<(), ConnectError> {
        debug_assert!(self.connection_client.is_some());

        let network_map = &self.network_map;

        let local_nid = self.local_nac.get_id();
        // Get the location information: the point type, and the central server nid of that point. The iCID is zero if this route is purely HyperLAN based
        let (endpoint_relative_point_type, central_server_nid, interserver_cid_opt) = *network_map.read().get_peer_location(route_dest_cid).unwrap();
        // now, we have to determine what route must be added to the [PacketStore] internally
        if !self.local_is_server {
            // The NID should NEVER be disclosed to a client to prevent knowledge of "what other clients" a particular node be be attributed to it
            debug_assert!(route_dest_nid.is_none());
            let local_cid = self.connection_client.unwrap().get_id();

            let (route_exp, route_no_exp) = match endpoint_relative_point_type {
                HYPERLAN_SERVER => {
                    // [1] HyperLAN Client -> HyperLAN Server
                    // We use a dest_server_nid of ZERO because a zero-nid implies one's HyperLAN Server by default
                    let route_exp = PacketRoute::new_hyperlan_client_to_hyperlan_server(local_nid, route_dest_cid, 0, true, network_map).into_result().map_err(|_| ConnectError::BadRoute)?;
                    let route_no_exp = PacketRoute::new_hyperlan_client_to_hyperlan_server(local_nid, route_dest_cid, 0, false, network_map).into_result().map_err(|_| ConnectError::BadRoute)?;
                    (route_exp, route_no_exp)
                },

                HYPERLAN_CLIENT => {
                    // [2] HyperLAN Client -> HyperLAN Client
                    let route = PacketRoute::new_client_to_client(local_cid, local_nid, route_dest_cid, network_map).into_result().map_err(|_| ConnectError::BadRoute)?;
                    // We cannot denote the intention of expects_response because the next hop does NOT equal the rebound point. As such, we duplicate the route and insert.
                    // Program logic other than this does not need to change, because expects_response will be imprinted upon the packet per usual, and it's that field that
                    // is used to determine the appropriate action
                    (route, route.clone())
                },

                HYPERWAN_SERVER => {
                    // [3] HyperLAN Client -> HyperWAN Server
                    debug_assert_eq!(route_dest_cid, interserver_cid_opt);

                    let route = PacketRoute::new_hyperlan_client_to_hyperwan_server(local_nid, local_cid, interserver_cid_opt, network_map).into_result().map_err(|_| ConnectError::BadRoute)?;
                    // We cannot denote the intention of expects_response because the next hop does NOT equal the rebound point. As such, we duplicate the route and insert.
                    // Program logic other than this does not need to change, because expects_response will be imprinted upon the packet per usual, and it's that field that
                    // is used to determine the appropriate action
                    (route, route.clone())
                },

                HYPERWAN_CLIENT => {
                    // [4] HyperLAN Client -> HyperWAN Client
                    let route = PacketRoute::new_client_to_client(local_cid, local_nid, route_dest_cid, network_map).into_result().map_err(|_| ConnectError::BadRoute)?;
                    // We cannot denote the intention of expects_response because the next hop does NOT equal the rebound point. As such, we duplicate the route and insert.
                    // Program logic other than this does not need to change, because expects_response will be imprinted upon the packet per usual, and it's that field that
                    // is used to determine the appropriate action
                    (route, route.clone())
                },

                n => {
                    panic!("Invalid relative point type {}", n)
                }
            };

            self.packet_route_store.add_route(route_dest_cid, route_exp, route_no_exp)
        } else {

            // if the local node is a server, then we have possibility [5] or [6] or [7]
            let (route_exp, route_no_exp) = match endpoint_relative_point_type {
                HYPERLAN_CLIENT => {
                    // [5]: HyperLAN Server -> HyperLAN Client
                    let route_exp = PacketRoute::new_hyperlan_server_to_hyperlan_client(local_nid, route_dest_cid, true, network_map).into_result().map_err(|_| ConnectError::BadRoute)?;
                    let route_no_exp = PacketRoute::new_hyperlan_server_to_hyperlan_client(local_nid, route_dest_cid, false, network_map).into_result().map_err(|_| ConnectError::BadRoute)?;
                    (route_exp, route_no_exp)
                },

                HYPERWAN_SERVER => {
                    // [6]: HyperLAN Server -> HyperWAN Server (interserver)
                    debug_assert_eq!(route_dest_cid, interserver_cid_opt);
                    debug_assert!(route_dest_nid.is_some());

                    let route_dest_nid = route_dest_nid.unwrap();
                    let route_exp = PacketRoute::new_interserver(local_nid, route_dest_nid, true, network_map).into_result().map_err(|_| ConnectError::BadRoute)?;
                    let route_no_exp = PacketRoute::new_interserver(local_nid, route_dest_nid, false, network_map).into_result().map_err(|_| ConnectError::BadRoute)?;
                    (route_exp, route_no_exp)
                },

                HYPERWAN_CLIENT => {
                    // [7]: HyperLAN Server -> HyperWAN Client
                    debug_assert!(route_dest_nid.is_none()); // Per network rules, we cannot know the NID of a HyperWAN Client
                    let route = PacketRoute::new_hyperlan_server_to_hyperwan_client(local_nid, route_dest_cid, network_map).into_result().map_err(|_| ConnectError::BadRoute)?;
                    // We cannot denote the intention of expects_response because the next hop does NOT equal the rebound point. As such, we duplicate the route and insert.
                    // Program logic other than this does not need to change, because expects_response will be imprinted upon the packet per usual, and it's that field that
                    // is used to determine the appropriate action
                    (route, route.clone())
                },

                n => {
                    panic!("Invalid relative point type {}", n)
                }
            };

            self.packet_route_store.add_route(route_dest_cid, route_exp, route_no_exp)
        }
    }

    /// Sometimes, a signal needs to be sent across to the adjacent node and no-one else. The payload is
    /// entirely optional, and if existent, can optionally be encrypted, but only with the latest
    /// encryption version. Regardless if a payload exists or not, a WID and PID are needed for the safe
    /// transmission of data to prevent man-in-the-middle attacks from spoofed packet headers.
    ///
    /// `expects_response`: If true, then at most 1 return packet is expected; the [StageDriver]
    /// will expect a signal, but not an object
    pub fn send_oneshot_signal<T: AsRef<[u8]>>(&self, command_flag: u8, security_level: SecurityLevel, payload: Option<&T>, expects_response: bool) -> Result<Option<StageDriverPacket>, ConnectError> {
        self.is_client_active()?;

        let cnac = self.connection_client.as_ref().unwrap();
        match cnac.read().toolset.get_most_recent_drill() {
            Some(drill) => {
                let eid_oid = self.handle.tally_and_get_eid_oid(1) as u64;
                let (self_node_type, adjacent_node_type) = self.get_node_type_info();
                let packet = craft_oneshot_signal(eid_oid, command_flag, DEFAULT_AUXILIARY_PORTS[0], DEFAULT_AUXILIARY_PORTS[0],
                                                  self_node_type, adjacent_node_type, self.is_server(), self.network_map.read().get_version(), &self.local_nac,
                                                  self.connection_client.as_ref().unwrap(), security_level, drill, payload, expects_response).map_err(|err| ConnectError::Generic(err.to_string()))?;

                match self.send_packet_layout(packet) {
                    Ok(_) => {
                        if expects_response {
                            self.create_expectancy(drill.get_cid(), eid_oid, security_level, None, true).await
                        } else {
                            Ok(None)
                        }
                    },

                    Err(err) => Err(err)
                }

            },

            None => {
                Err(ConnectError::DrillAbsent)
            }
        }
    }

    /// Sends data outbound via the underlying [ConnectionHandle]. The data should NOT be encrypted.
    /// This handles the encryption of data, as well as waveform modulation, splitting, scrambling, etc.
    ///
    /// NOTE: The CNAC and NAC should NOT have any non-recursive read calls in the closure from which
    /// this is called, otherwise, a deadlock may happen.
    ///
    /// `expects_response`: If this value is `false`, then this function will return Ok(None) upon the
    /// success of a save. Else if, this value is `true`, then this function may possibly return
    /// Ok(Some(&mut packet)). Specifying `true` does not guarantee a packet will arrive because of
    /// downstream errors in possible network transmissions, configuration, etc.
    ///
    /// `command_flag`: The signal should be obtained from crate::packet::flags.rs
    ///
    /// `packet_route`: This must be properly constructed with parameters that are relative to the current
    /// node. Id est, the packet route must be updated first before inputting them herein.
    ///
    /// `packet_route.route_dest_cid`: If the value is zero, the data is sent to the `adjacent_node` (whether
    /// that be a central server or a client). If the value is nonzero, then it implies the packet must make at
    /// least n=1 hops. For example, if local client C is bridged with central server S, inputting a
    /// nonzero `cid_to` could imply either: A HyperLAN client, or, a HyperWAN client. For instead
    /// sending data directly to a HyperWAN server for purposes of registration, use the register_ext
    /// subroutine.
    #[allow(unused)]
    pub async fn send_data_across_bridge<Drx: DrillType, T: AsRef<[u8]>>(&self, packet_route: PacketRoute, security_level: SecurityLevel, drill: &Drill<Drx>, data: Option<&T>, expects_response: bool) -> Result<Option<StageDriverPacket>, ConnectError> {
        self.is_client_active()?;

        //cid_original: u64, cid_needed_to_undrill: u64, drill_version_needed_to_undrill: u32, security_level_drilled: u8,
        //                 timestamp: i64,
        //                 current_packet_hop_state: u8, next_hop_state: u8, endpoint_destination_type: u8,
        //                 command_flag: u8, expects_response: u8,
        //                 oid_eid: u64, wid: u64, pid: u64,
        //                 route_dest_nid: u64, route_dest_cid: u64, network_map_version: u32
        if packet_route.route_dest_cid != 0 {
            // First, we need to query the local server to see if cid_to can be connected to. Regardless, data must first make its way across the bridge
            unimplemented!()
        } else {
            // Since cid_to is 0, we only have to send data across the bridge
            match self.state {
                BridgeState::OPEN => {
                    let cid = self.connection_client.get_id();
                    let eid_oid = self.handle.get_and_increment_objects_sent(); // TODO: Bug. Waves != packets
                    let data = data.unwrap_or(b"").as_ref();

                    match craft_send_data(data, eid_oid as u64, drill, packet_route, security_level, expects_response, PORT_START) {
                        Ok(packets) => {
                            // The data at this point is under the supervision of the lower-level ConnectionHandle -> codec -> network layer
                            // Now, we just have to register a listener if this packet or wave expects a response
                            // Also, update the packet count now that we know how many packets there are
                            self.handle.get_and_increment_packets_sent_by(packets.len());
                            if expects_response == 1 {
                                self.send_packet_layouts(packets, Some((cid, oid_eid as u64, security_level, None, false))).await
                            } else {
                                self.send_packet_layouts(packets, None).await
                            }
                        },

                        Err(err) => Err(ConnectError::Generic(err.to_string()))
                    }
                },

                _ => {
                    Err(ConnectError::BridgeClosed)
                }
            }
        }
    }

    /// Sends a barrage of packets outbound. This is called by the higher-level subroutines within this [BridgeHandler]
    /// `expectancy_request_params`:
    async fn send_packet_layouts(&self, packets: Vec<PacketLayout0D>, expectancy_request_params: Option<(u64, u64, SecurityLevel, Option<usize>, bool)>) -> Result<Option<StageDriverPacket>, ConnectError> {
        for layout in packets {
            self.send_packet_layout(layout)?
        }

        match expectancy_request_params {
            Some(exp) => {
                self.create_expectancy(exp.0, exp.1, exp.2, exp.3, exp.4).await
            },

            None => {
                Ok(None)
            }
        }
    }

    /// All subroutines which seek to send data and/or signals via the [BridgeHandler] inevitably send data through here (metaphoric pinch-point)
    #[inline]
    fn send_packet_layout(&self, packet: PacketLayout0D) -> Result<(), ConnectError> {
        self.handle.send_outbound(packet.port_mapping.0, packet.port_mapping.1, packet.data)
    }

    async fn create_expectancy(&self, cid: u64, eid_oid: u64, security_level: SecurityLevel, response_size: Option<usize>, is_signal: bool) -> Result<Option<StageDriverPacket>, ConnectError> {
        let request = {
            if response_size.is_some() {
                if is_signal {
                    ExpectancyRequest::Singleton(cid, eid_oid, SINGLETON_EXPECTANCY_TIMEOUT, security_level)
                } else {
                    let resp_size = response_size.unwrap();
                    ExpectancyRequest::Object(cid, eid_oid, resp_size, Self::calculate_timeout(resp_size), security_level)
                }
            } else {
                ExpectancyRequest::Auto(cid, eid_oid, Self::calculate_timeout(0), security_level)
            }
        };

        match self.stage_driver_handle.request_expectancy(request) {
            Ok(resp) => {
                match (*resp).await {
                    Some(packet) => {
                        Ok(Some(packet))
                    },

                    None => {
                        Ok(None)
                    }
                }
            },

            Err(err) => Err(err)
        }
    }

    /// Calculates the timeout for an object of an expected size. A minimum of SINGLETON_EXPECTANCY_TIMEOUT will be returned
    fn calculate_timeout(size: usize) -> u64 {
        SINGLETON_EXPECTANCY_TIMEOUT + ((100*size) / AVERAGE_WORLDWIDE_DOWNLOAD_RATE) // for each 2.75 Mb of data, add 100 ms.
    }

    /// This subroutine takes-in a mutable reference to the packet data to help enforce zero-copy. This only
    /// updates some of the values in the header. There is a forward call within the packet that is called
    /// for updating those values. As such, the purpose of this function is to:
    ///
    /// [1] Update any values in the header as per current header contents within `packet`, and;
    /// [2] Send the packet outbound*
    ///
    /// Ensure: the packet's payload is ready to be dispatched outbound, and; the cryptographic information
    /// within the header is already set and its metadata can be used to decrypt the payload, and;
    ///
    /// [*] This uses the recv_port as both the send port and destination_port. It assumes the receive port
    /// is equal across all future sends. This is meant for signals. Only packets which traverse across the
    /// auxiliary ports will be allowed to use this function call
    ///
    /// Since the outbound direction is already known to be the adjacent node in the bridge, the packet has
    /// the basic amount of information needed to be forwarded. HOWEVER, this also requires that the header
    /// has a properly embedded [PacketRoute], otherwise, downstream forwarding/response validity is truly
    /// unknown.
    pub fn forward_singleton_packet(&self, mut packet: StageDriverPacket) -> Result<(), ConnectError> {
        translate_packet_route_details(&mut packet, &self.network_map)?;
        let (send_port, remote_recv_port) = (packet.get_receive_socket().port(), packet.get_sender().port());

        self.send_packet_layout(PacketLayout0D {
            data: packet.get_bytes().to_vec(),
            port_mapping: (send_port, remote_recv_port)
        })
    }

    /// In the case that the client or server wishes to register with an [ext]ernal server, the subroutine must
    /// be called. If the NID is already known, and the NID has a valid mapping with the central server, `nid_ext`
    /// can be supplied. If the IP address is instead known, then `ip_addr_ext` can be specified. Supplying both
    /// will result in a panic. Supplying None for both will also result in a panic.
    pub async fn register_ext(&self, nid_ext: Option<u64>, ip_addr_ext: Option<IpAddr>) -> Result<(), ConnectError> {
        assert!((nid_ext.is_some() && ip_addr_ext.is_none()) || (nid_ext.is_none() && ip_addr_ext.is_some()));
        unimplemented!()
    }

    /// During the login process, the [ServerBridgeHandler] awaits 22 tubes (20 wave ports + 2 auxiliary ports).
    ///
    /// This returns Ok(true) if all the tubing is loaded
    pub fn inject_tubing(&mut self, local_port: u16, stream_outbound_tx: UnboundedSender<OutboundItem>, stream_signal_tx: Sender<u8>) -> Result<bool, ConnectError> {
        self.handle.inject_tubing(local_port, stream_outbound_tx, stream_signal_tx)
    }

    /// This function will abruptly shutdown all the stream via the lower-level [ConnectionHandle]. It is the duty
    /// of the caller to ensure that a safe-shutdown is performed. This is also used for terminating an unsuccessful
    /// login initiation, and as such, whether or not this bridge is open does not change the steps in logic this
    /// subroutine executes
    pub unsafe fn shutdown(&mut self) -> Result<(), ConnectError> {
        self.handle.shutdown()
    }

    /// Once a [DO_LOGIN_SUCCESS] packet arrives, the [ServerBridgeHandler] must update these two items which were
    /// left only partially or incompletely initialized:
    ///
    /// [1] The CNAC* with either CID or iCID type, implicated in the connection (left as `None`), and;
    /// [2] The routing info, since this process is omitted when a bridge is being established between this node and
    /// a server node. We must add the [PacketRoute]'s to the internal [PacketRouteStore]
    ///
    /// [*] Before this subroutine is called, it is expected that the [DO_LOGIN_SUCCESS] occurs as a result of a
    ///     successful login. This necessarily implies the existence of the CNAC, and as such, we can debug-assert
    ///     the existence of the CNAC within `account_manager`
    /// Panics (debug stage): if the CNAC is initialized and/or the adjacent node NAC is not zero-initialized
    pub fn cxn_init_cnac(&mut self, nid: u64, cid: u64, remote_client: &IpAddr, account_manager: &AccountManager) -> bool {
        debug_assert!(self.connection_client.is_none()); // This should not yet be initialized
        debug_assert!(self.local_is_server); // Should be a server type running this bridge

        // We must fetch the CNAC from the local store. It is expected by this point that the CNAC exists, since the login was a success
        let mut cnac = account_manager.get_client_by_cid(cid).unwrap();
        debug_assert_eq!(cnac.get_id(), cid);

        if cnac.validate_ip(remote_client, PINNED_IP_MODE) {
            let network_map_version = self.network_map.read().get_version();
            let local_nid = self.local_nac.get_id();

            let nid_opt = {
                if cnac.read().is_hyperwan_server {
                    // This is thus an interserver connection, and we need a NID since this is known to us when the type is a local
                    // server (already asserted to be true) and the point is directly adjacent to us. We must thus pass Some(nid)
                    Some(nid)
                } else {
                    None
                }
            };

            self.add_packet_route(cid, nid_opt, account_manager).is_ok()
        } else {
            eprintln!("[BridgeHandler] PIM check failed. Client {} from IP {} does not match the previously stored IP of {}", cid, remote_client, cnac.read().nac.get_addr(PREFER_IPV6).unwrap());
            false
        }
    }

    /// Determines if the current connection's local node is a server (returns true) or client (returns false) type
    pub fn is_server(&self) -> bool {
        self.handle.is_listener()
    }

    /// Returns self's node type, followed by the adjacent peer's node type.
    ///
    /// If self is a [HYPERLAN_CLIENT], then by topological necessity, the adjacent node is always a [HYPERLAN_SERVER],
    /// otherwise, one of two scenarios is possible:
    ///
    /// [1] Self is a HyperLAN Server and connected to a HyperLAN Client, or;
    /// [2] Self is a HyperLAN Server and connected to a HyperWAN Server
    ///
    /// However, under no circumstance can Self be a pure server listener. Doing so will result in a panic
    fn get_node_type_info(&self) -> (u8, u8) {
        debug_assert!(self.connection_client.is_some());

        if self.is_server() {
            if self.connection_client.as_ref().unwrap().read().is_hyperwan_server {
                (HYPERLAN_SERVER, HYPERWAN_SERVER)
            } else {
                (HYPERLAN_SERVER, HYPERLAN_CLIENT)
            }
        } else {
            (HYPERLAN_CLIENT, HYPERLAN_SERVER)
        }
    }

    fn is_client_active(&self) -> Result<(), ConnectError> {
        if self.state == BridgeState::CLOSED {
            return Err(ConnectError::BridgeClosed)
        }

        if self.connection_client.is_none() {
            return Err(ConnectError::CNACNotLoaded)
        }

        Ok(())
    }

}