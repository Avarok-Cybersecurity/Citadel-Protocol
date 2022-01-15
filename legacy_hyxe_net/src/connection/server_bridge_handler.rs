use futures::sync::mpsc::{Receiver, Sender, unbounded, UnboundedSender, channel, UnboundedReceiver};
use tokio_threadpool::Sender as ThreadPoolSender;
use futures::{Future, Stream, Sink};
use crate::packet::misc::ConnectError;
use hyxe_user::network_account::NetworkAccount;
use crate::packet::inbound::stage_driver::StageDriverHandle;
use crate::connection::connection::ConnectionHandle;
use std::pin::Pin;
use std::collections::HashMap;
use crate::connection::stream_wrappers::old::{OutboundItem, RawInboundItem};
use crate::connection::bridge_handler::{BridgeState, BridgeHandler};
use hyxe_user::account_manager::AccountManager;
use crate::packet::definitions::{LOGIN_PORT, REGISTRATION_PORT, LOCAL_BIND_ADDR, DEFAULT_IP_VERSION, PORT_START, PORT_END, DEFAULT_NETWORK_STACK_PROTOCOL, DEFAULT_ENCODING_SCHEME, DEFAULT_AUXILIARY_PORTS};
use crate::packet::flags::{connect, registration};
use crate::connection::{STREAM_SHUTDOWN, STREAM_RESTART};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use chashmap::CHashMap;
use crate::connection::network_map::NetworkMap;
use crate::connection::session::Session;
use hyxe_netdata::packet::{StageDriverPacket, PacketStage};
use crate::routing::PacketRoute;
use crate::connection::bridge_packet_processor::connect::{do_login_success, do_login_failure};
use crate::connection::registration::registration_handler::RegistrationHandler;
use crate::connection::bridge_packet_processor::registration::process_registration_signal;

/// This allows for creating client [Sessions] given an input of a new stream
pub struct ServerBridgeHandler<'cxn, 'driver: 'cxn, 'server: 'driver> {
    /// This allows for creating new connections for clients. The zeroth-index [ConnectionHandle] pushes two types of tubes to this
    /// [ServerBridgeHandler]:
    /// [1] Unbounded outbound data sender, for direct sending of data
    /// [2] Bounded stream signaller, for stopping and restarting the stream as necessary
    /// [->] Furthermore, the remote peer's [SocketAddress] coupled with the local port allows the [ServerBridgeHandler] to create the appropriate
    /// entries within `connection_handles`, and eventually, allowing the creation of a higher-level [Session]
    new_tubing_channel: Option<(UnboundedSender<(IpAddr, u16, UnboundedSender<OutboundItem>, Sender<u8>)>, UnboundedReceiver<(IpAddr, u16, UnboundedSender<OutboundItem>, Sender<u8>)>)>,
    /// The [ServerBridgeHandler] plays a unique role which breaks symmetry with the common process applied to the [ConnectionHandle].
    /// Whereas a pure client session [BridgeHandler] creates and then self-fills the [ConnectionHandle], the [ServerBridgeHandler]
    /// must follow this process:
    /// [1] listen to all ports including auxiliary ports via the zeroth-index `connection_handles`
    ///
    /// [2] await for a new peer to connect to the first auxiliary port. The [ConnectionHandle] then sends, via-channel, the tubing
    /// to this [ServerBridgeHandler]. Those two tubes are the outbound_tx (for sending data) and signal_tx (for stopping the stream)
    ///
    /// [3] Since the inbound_tx tubing is connected directly to the [StageDriver], this [ServerBridgeHandler] can't "expect" a login signal
    /// per-se. Instead, it is up to the [StageDriver] to alert this [ServerBridgeHandler]. Regardless, the metaphoric role of either
    /// [BridgeHandler] or [ServerBridgeHandler] is to serve as a pinch point mediator for data before being sent to the higher-level API layer.
    /// Therefore, step [3] in the process is for this [ServerBridgeHandler] to inject an empty-skeleton [ConnectionHandle] filled with
    /// only the first-auxiliary port's stream tubing (which it has thus-far received).
    ///
    /// [4] With the tubing injected into a newly created empty [ConnectionHandle], the [ServerBridgeHandler] awaits for a signal forwarded
    /// from the [StageDriver] that translates the DO_LOGIN signal with either a DO_LOGIN_SUCCESS or DO_LOGIN_FAILURE. With the login being
    /// successful*, the [ServerBridgeHandler] then sends a DO_LOGIN_SUCCESS signal back through the injected tubing to the adjacent peer
    /// (via the first auxiliary port)
    ///
    /// [5] Assuming the result from step [4] was a success, the [ServerBridgeHandler] then awaits for tubing to be sent from the zeroth-index
    /// server listener [ConnectionHandle] for all primary ports as well as the second auxiliary port. Once all the tubing is received, the
    /// a new [Session] is created with the [BridgeHandler] which stored the [ConnectionHandle] (the [BridgeHandler] within `bridges` now must
    /// be removed and placed within a new [Session])
    ///
    /// [*] If the login is a failure, then a DO_LOGIN_FAILURE signal is sent via the injected tubing, and thereafter that tubing gets removed
    pub(crate) bridges: CHashMap<IpAddr, BridgeHandler<'cxn, 'driver>>,
    /// Once a connection has been made valid, the bridge is removed from `bridges` and thereafter MOVED into a [Session] below (pins to the heap
    /// still remain valid, however, as we are not altering the location of the pointee)
    pub(crate) sessions: CHashMap<u64, Session<'cxn, 'driver, 'server>>,
    /// A loop 'de loop, from the topological perspective of the metaphor. It uses an array of listeners rather than streams
    server_loopback_bridge: Option<BridgeHandler<'cxn, 'driver>>,
    /// This is just for allowing reconnection at the lower-levels when reconnect is called at this layer of abstraction via the signal tubes
    stream_to_stage_driver_tx: UnboundedSender<RawInboundItem>,
    /// Packets which are processed from the [StageDriver] are forwarded to this layer for processing
    inbound_from_stage_handler: Option<UnboundedReceiver<StageDriverPacket>>,
    stage_driver_handle: StageDriverHandle<'cxn, 'driver, 'server>,
    pub(crate) registration_handler: RegistrationHandler<'cxn, 'driver, 'server>,
    pub(crate) account_manager: AccountManager,
    pub(crate) network_map: NetworkMap,
    pub(crate) local_nac: NetworkAccount,
    /// This provides a pinch-point for all requests. At the flick of the wand, the server can prevent all outbound traffic
    pub(crate) state: BridgeState
}

impl<'cxn, 'driver: 'cxn, 'server: 'driver> ServerBridgeHandler<'cxn, 'driver, 'server> {
    /// Creates a new [ServerBridgeHandler]. This allows for message-passing and creation of expectancies via the
    /// `stage_driver_handle`. This should be called by the higher-level [Session] type.
    pub fn new(threadpool_sender: ThreadPoolSender, stage_driver_handle: StageDriverHandle, stream_to_stage_driver_tx: UnboundedSender<RawInboundItem>, stage_driver_output: UnboundedReceiver<StageDriverPacket>, local_nac: NetworkAccount, network_map: NetworkMap, account_manager: AccountManager) -> Pin<Box<Self>> {
        let zeroth_index_connection_handle = ConnectionHandle::default_server();
        let zeroth_index_bridge = BridgeHandler::new(stage_driver_handle, zeroth_index_connection_handle, None, &local_nac, network_map.clone(), true);

        let mut bridges = CHashMap::new();

        let registration_handler = RegistrationHandler::new(threadpool_sender, stage_driver_handle.clone(), local_nac.clone());

        Box::pin( Self { new_tubing_channel: Some(unbounded()), bridges, sessions: Default::default(), server_loopback_bridge: Some(zeroth_index_bridge), stream_to_stage_driver_tx, inbound_from_stage_handler: Some(stage_driver_output), stage_driver_handle, registration_handler, account_manager, network_map, local_nac: local_nac.clone(), state: BridgeState::CLOSED } )
    }

    /// Begins the underlying client connection by asynchronously executing the lower-level [ConnectionHandle] in stream-mode.
    ///
    /// This is called by the higher-level containing [SessionManager]
    ///
    /// This will panic if the zero-index connection handle does not exist. This is possible if the server is stopped, and then
    /// the zero-index is not re-added or re-created
    /// `stream_to_stage_driver` (now omitted): In the event of a restart, the streams will need the means of reconnecting itself to the [StageDriver]
    /// `remote_rx`: This allows the higher-levels to stop/restart the server on-command
    pub async fn start_server(mut self: Pin<&'server mut Self>, remote_rx: Receiver<u8>) -> Result<(), ConnectError> {
        let mut zero_index_connection_handle = self.server_loopback_bridge.take().unwrap(); // This will cause a panic if the server was restarted and not reloaded properly
        let (connection_sender, connection_receiver) = self.new_tubing_channel.take().unwrap();
        let stream_to_stage_driver_tx = self.stream_to_stage_driver_tx.clone();

        let self_ptr = self as *const Self;

        // Since this layer of abstraction receives packets from the [StageDriver], it is necessary to handle these packets via this subroutine
        let packet_receiver = self.inbound_from_stage_handler.take().unwrap();

        // Since the zero-index connection handle is pinned, its memory location will stay constant. How about data race safety?
        // Well, considering all these futures are selected() -- meaning, they all stop once one returns -- the below future will
        // cause all others to exit simultaneous to receiving a signal (a valid signal)
        let zero_index_cxn_handle_ptr = &mut zero_index_connection_handle.handle as *mut ConnectionHandle;

        unsafe {
            zero_index_connection_handle
                .start_server(inbound_tx, &connection_sender) // Starts the underlying streams which forward data to the [StageDriver]
                .select(self_ptr.connection_creator(connection_receiver)) // starts the means for creating new connections from the underlying listeners
                .map_err(|err| err.0)
                .map(|_| ())
                .select(self_ptr.inbound_packet_handler(packet_receiver)) // Starts the means for forwarding packets from the [StageDriver] to this abstraction layer
                .map_err(|err| err.0)
                .map(|_| ())
                .select(self_ptr.remote_handle(zero_index_cxn_handle_ptr, stream_to_stage_driver_tx, remote_rx)) // Starts the means for stopping/restarting the server
                .map_err(|err| err.0)
                .map(|_| ())
                .and_then(|_| Ok(()))
        }
    }

    /// The internal server-listeners found within the `server_loopback_bridge` must be able to take newly created client-streams and then send the tubing upwards. This allows
    /// this layer of abstraction to manage the client-streams.
    unsafe async fn connection_creator(self: *const Self, new_tubing_receiver: UnboundedReceiver<(IpAddr, u16, UnboundedSender<OutboundItem>, Sender<u8>)>) -> Result<(), ConnectError> {
        new_tubing_receiver.map_err(|_| ConnectError::Generic("".to_string())).map(|(addr, local_port, stream_outbound_tx, stream_signal_tx)| {
            let this = &*self;
            match local_port {
                LOGIN_PORT => {
                    // At this point, step [1] and step [2] is done. Now, we have to create an empty [ConnectionHandle] and insert the zeroth-index auxiliary-port tubing
                    if !this.bridges.contains_key(&addr) {
                        println!("[ServerBridgeHandler] Beginning connection initiation process for {}", &addr);
                        // We set local_is_server to true, because this connection was instantiated as a response from an external client
                        let mut bridge = BridgeHandler::new(this.stage_driver_handle.clone(), ConnectionHandle::default_client(addr), None, &this.local_nac, this.network_map.clone(), true);
                        // inject the first-auxiliary port tubing
                        bridge.inject_tubing(local_port, stream_outbound_tx, stream_signal_tx).unwrap(); // this should always unwrap as ok
                        // The bridge is loaded
                        this.bridges.insert_new(addr, bridge);
                        // Now that the bridge has been inserted, new connection tubes may be added to it. We have finished step 3. Step 4 occurs under the `inbound_packet_handler` subroutine below
                    } else {
                        eprintln!("[ServerBridgeHandler] A connection attempt from {} was denied due to a pre-existing connection by the same IP Address", addr);
                        let _ = stream_signal_tx.send(STREAM_SHUTDOWN);
                    }
                },
                
                REGISTRATION_PORT => {
                    // TODO: Forward to registration subroutine. Check to ensure that this is a valid signal: no concurrent bridges, not existent in [NetworkMap], etc
                    if !this.bridges.contains_key(&addr) {
                        // Since we have not yet received a packet, what we need to do is store the tubing into the [RegistrationHandler]. This allows us to post an expectancy into the [StageDriver],
                        // and later-on via `inbound_packet_handler` in the below subroutine, handle the resultant object-packet; thereafter, it then matches the source IP of the packet
                        println!("[ServerBridgeHandler] Beginning registration initiation process for {}", &addr);
                        // We must pass the tubing to the internal [RegistrationHandler]...
                        if this.registration_handler.process_stage0_server_registration_signal(addr, stream_outbound_tx, stream_signal_tx).is_err() {
                            let _ = stream_signal_tx.clone().send(STREAM_SHUTDOWN);
                        }
                        // registration tubing added; this subroutine no longer has to do anything else for this particular connection
                    } else {
                        eprintln!("[ServerBridgeHandler] A registration attempt from {} was denied due to a pre-existing connection by the same IP Address", addr);
                        let _ = stream_signal_tx.send(STREAM_SHUTDOWN);
                    }
                },
                
                wave_port => {
                    // This should only be step 5, meaning: the login was successful, and now, we are adding tubing until 22 tubes exist within the bridge handler
                    //********** Step 5 of the login process **********
                    
                    match this.bridges.get_mut(&addr) {
                        Some(mut bridge) => {
                            // Bridge existed as expected, now, we just have to inject the tubing and check to see if it's done
                            match bridge.inject_tubing(local_port, stream_outbound_tx, stream_signal_tx) {
                                Ok(true) => {
                                    // All tubes loaded; Send (a second) DO_LOGIN_SUCCESS
                                },
                                
                                Ok(false) => {
                                    // more tubes needed still ...
                                },
                                
                                Err(err) => {
                                    eprintln!("[ServerBridgeHandler] Unable to inject tubing. Reason: {}", err.to_string());
                                    let _ = stream_signal_tx.send(STREAM_SHUTDOWN); // shutdown this stream, since it isn't going to be added into the bridge
                                    let _ = bridge.shutdown(); // shutdown all other possible streams abruptly
                                }
                            }
                        },
                        
                        None => {
                            eprintln!("[ServerBridgeHandler] A connection was attempted on wave-port {}, but did not signal the login port prior. Dropping stream", local_port);
                            let _ = stream_signal_tx.send(STREAM_SHUTDOWN);
                        }
                    }
                }
            }
        }).and_then(|_| Ok(()))
    }

    /// The purpose of this function is to receive the output from the [StageDriver].
    /// `packet_receiver`: The tubing which receives data from the driver, and receives data for all possible clients and servers.
    unsafe async fn inbound_packet_handler(self: *const Self, packet_receiver: UnboundedReceiver<StageDriverPacket>) -> Result<(), ConnectError> {
        packet_receiver.map(|mut packet| {
            let this = &*self;
            let header = packet.get_header();
            // We must check the packet to see if it contains a unique signal type that is relevant for this abstraction layer. E.g.,
            // a DO_LOGIN packet. However, the [StageDriver] overwrites the header of the DO_LOGIN packet with either a DO_LOGIN_SUCCESS
            // or a DO_LOGIN_FAILURE
            match header.command_flag {
                connect::DO_LOGIN_SUCCESS => {
                    // Step 4
                    do_login_success(this, packet)
                },

                connect::DO_LOGIN_FAILURE => {
                    // Step 4 / terminate
                    do_login_failure(this, packet)
                },

                // § Reserved Section 50s (registration signals)
                x if x >= 50 && x < 60 => {
                    // registration signals take advantage of an otherwise empty oid_eid field, and use it to point to the next expected action.
                    // By the time of receiving the signal within the closure, that "next expected action" is simply the action we must now execute
                    process_registration_signal(this, packet)
                },

                _ => {
                    // We must look for the [Session] which matches the packet's CID. The stage driver guarantees that the CID exists in a local map,
                    // however, nothing is guaranteeing that it is logged-in
                    
                }
            }
        }).and_then(|_| Ok(()))
    }

    /// This allows the owner of the higher-level [Server] to stop/restart the entire networking layer of this program.
    /// `zero_index_cxn_handle_ptr`: The pointee must be heap-pinned in order for this to be safe
    unsafe async fn remote_handle(self: *const Self, zero_index_cxn_handle_ptr: *mut ConnectionHandle, stream_to_stage_driver: UnboundedSender<RawInboundItem>, remote_rx: Receiver<u8>) -> Result<(), ConnectError> {
        remote_rx.map(|signal| {
            match signal {
                STREAM_SHUTDOWN => {
                    println!("[AsyncStreamHandler] Shutting down streams");
                    // TODO: Perform safe-shutdown on all possibly existent streams
                    let _ = (&mut *zero_index_cxn_handle_ptr).shutdown();
                    Err(ConnectError::Shutdown)
                },

                STREAM_RESTART => {
                    println!("[AsyncStreamHandler] Restarting stream");
                    unimplemented!("Restarting the stream is not yet implemented. Please manually stop and start the server to emulate the equivalent functionality of a restart");
                    let _ = (&mut *zero_index_cxn_handle_ptr).restart_connection(&stream_to_stage_driver, Some(connection_sender));
                    Err(ConnectError::Restart)
                },

                _ => {
                    println!("[AsyncStreamHandler] unknown command!");
                    Ok(())
                }
            }
        }).and_then(|_| Ok(()))
    }

    /// This creates a connection handle given a particular CID and IpAddr.
    /// This will fetch the locally-stored [ClientNetworkAccount] and construct a [NetworkAccount]
    /// to place therein. Thereafter, it will create a [Session]
    fn create_session_by_cid(&self, cid: u64, addr: IpAddr) -> Option<Session> {
        match self.account_manager.get_client_by_cid(cid) {
            Some(cnac) => {
                let write = cnac.write();
                // There cannot exist a loaded-nac, otherwise, it implies either faulty save/load logic, OR, a previously existing connection
                // that was cut abruptly within much
                if write.nac.is_none() {
                    // Good, there was nothing previously existent within this CNAC
                    write.nac.replace(NetworkAccount::from((cid, addr)));
                    //let sess = Session::new
                    None
                } else {
                    None
                }
            },

            None => {
                None
            }
        }
    }

    /// This is to be called upon an unsuccessfull login attempt
    pub(crate) fn terminate_bridge(&self, addr: &IpAddr) -> bool {
        self.bridges.remove(addr).is_some()
    }

    /// This returns the CID given an IP address. Note: it is possible that a HyperWAN server qualifies as
    /// a client
    fn get_cnac_by_ip(&self, addr: &IpAddr) -> Option<u64> {
        self.network_map.ge
    }
}
