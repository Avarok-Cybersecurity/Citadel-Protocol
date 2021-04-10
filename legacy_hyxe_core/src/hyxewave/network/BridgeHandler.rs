/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use core::borrow::BorrowMut;
use std::cell::RefCell;
use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam::{Receiver, Sender};
/**
    This structure provides methods for sending data between a server and client or vice versa.
    All higher-levelAPIs should make use of this. The interior system is asynchronous and delicatly
    created, and as such, using this structure is required for assurance of data delivery. There
    are two types of connections that can be made. For standard transactions of messages, images,
    and small files, use the KCP/ipv{4,6} protocol. For large file transfers, use UDT/ipv{4,6}.
    Please use ipv6 when available, as this is the future protocol for data transmission.
*/
//use crossbeam_channel::{Receiver, Sender, unbounded};
use crossbeam_queue::SegQueue;
use crossterm::{ClearType, Color, Crossterm};
use futures::future::{Executor, Future};
use futures::future::FutureResult;
use futures::prelude::*;
use futures::prelude::*;
use hashbrown::HashMap;
use parking_lot::Mutex;
use rayon::*;
use rayon::str::ParallelString;
use tokio::io::{Error, ErrorKind};
use tokio::prelude::{future, stream};
use tokio::reactor::Handle;
use tokio::timer::{Delay, Interval, Timeout};
use tokio_core::reactor::{Core, Remote};

use hyxe_util::HyxeError;
use tokio_kcp::KcpStream;

use crate::hyxewave::encrypt::WaveFormGenerator::PacketSeriesLayout;
use crate::hyxewave::misc::Constants;
use crate::hyxewave::misc::Globals;
use crate::hyxewave::misc::Utility::{generate_rand_u64, printf, printf_err, printf_success};
use crate::hyxewave::network::{PacketGenerator, SocketHandler};
use crate::hyxewave::network::ExpectanceHandler::*;
use crate::hyxewave::network::GUIConnector::{get_client_alerter, send_to_gui};
use crate::hyxewave::network::Packet::{OutboundPacket, Packet, ProcessedInboundPacket};
use crate::hyxewave::network::PacketProcessor::PacketSubtype;
use crate::hyxewave::network::session::NetworkAccount::NetworkAccount;
use crate::hyxewave::network::session::services::ConnectionWorker::check_connection_worker_async;
use crate::hyxewave::network::session::SessionHandler::{get_session, Session, SessionChecker};
use crate::hyxewave::network::WaveformListener::WaveformListener;
use crate::SecurityLevel;
use crate::tokio::prelude::FutureExt;

pub enum ConnectionType {
    KCP,
    UDT,
}

/// This is useful for determining the nature of any given BridgeHandler.
/// Is this node connected to a HyperLAN client (in the case of a HyperLAN Server)
/// or is the node connected to an external HyperWAN Server? the `is_server` variable
/// within the BridgeHandler determines our initial point on the network, and
/// the AdjacentPointState determines where the information is going. With these
/// two points, we can effectively assist the PackerRouter in making a decision as
/// to where a packet (may) need to hop next.
pub enum AdjacentPointState {
    HYPERLAN_CLIENT,
    HYPERWAN_SERVER,
}

#[derive(Default, Debug)]
pub struct BridgeHandler {
    pub ip_to: String,
    pub port_start: u16,
    pub port_end: u16,
    pub aux_ports: Vec<u16>,
    pub is_server: bool,
    pub sockets_are_alive: bool,
    pub can_check: bool,
    pub connected_to_peer: bool,
    pub check_connection_fail_count: usize,
    pub check_connection_fail_server_count: usize,
}

/// For each HyxeClient that is connected, there exists one active bridge to the central mainframe server and no more
/// For each HyxeServer that contains active connections, there exists multiple bridges. The bridge can connect to
/// and internal node in the HyperLAN, or it can connect directly to an external HyperWAN server. For security reasons
/// The HyxeServer cannot connect directly to an external HyperLAN client to increase anonymity.
///
/// If a [client wants to connect to an external client], the data must pass through multiple bridges, being decrypted and
/// re-encrypted with a new drillset at each node. Data goes from the client the central mainframe server for that client,
/// and then the central mainframe server must check to see if it has a SESSION with the external HyperWAN server. If there is
/// no session between the client's mainframe server and the necessary external HyperWAN server, then the client will be given
/// an error message. Depending on the mainframe server's admin, it may be possible to initiate a REGISTRATION, thus allowing
/// data to then flow between the HyperLAN server and the HyperWAN server. So long as there is a connection between the HyperLAN
/// server and the external HyperWAN, then data can flow from the initial client to the external HyperWAN server across the connection.
///
/// However, we are interested in the original idea, that [a client wants to connect to an external client]. In order for the
/// information to then go from the HyperWAN server to one of its HyperLAN clients (relatively a HyperWAN client to the initial
/// client), there must be a mutual registration on BOTH ENDS. Like in real life, there is a sort of permission that occurs before one
/// shares information with another. We are modelling this network like a normal, everyday life system. However, unlike real life
/// where permission can be violated by physical force, violating permissions on this network is virtually impossible.
///
impl BridgeHandler {
    pub fn new(ip_to: String, port_start: u16, port_end: u16, aux_ports: Vec<u16>, is_server: bool) -> Self {
        BridgeHandler { ip_to, port_start, port_end, aux_ports, is_server, sockets_are_alive: false, can_check: true, connected_to_peer: false, check_connection_fail_count: 0, check_connection_fail_server_count: 0 }
    }

    pub fn get_connect_data(&self) -> (&String, &u16) {
        (&self.ip_to, &self.aux_ports.get(0).unwrap())
    }

    pub fn send_packet_simple_sync(&self, packet: ProcessedInboundPacket) -> bool {
        if self.connected_to_peer || self.is_server {
            println!("[BridgeHandler] Sending a simple packet!");
            let key = format!("{}:{}", packet.get_dest_ip().clone().to_owned(), packet.get_dest_port().clone().to_owned());

            println!("The key is {}", &key);
            let (dest_ip, dest_port, message) = (packet.get_dest_ip(), packet.get_dest_port(), &packet.get_message());

            let message = base64::encode(message);
            println!("Message is (len={}): {}", &message.len(), &message);
            let send_opt = SocketHandler::acquire_sender(&packet.get_dest_ip(), &packet.get_dest_port());
            if send_opt.is_none() {
                eprintln!("[BridgeHandler] Unable to acquire sender: is absent!");
                return false;
            }

            let send = send_opt.unwrap();
            send.lock().push(message);
            //notify handle
            Globals::SOCKET_TASKS_INPUT.lock().get(&key).unwrap().lock().notify();
            return true;
        }

        return false;
    }

    pub fn send_packet_async<F>(&self, remote: Remote, mut packet: OutboundPackett, on_response_received: Option<F>) where F: Fn(Option<ProcessedInboundPacket>, Remote) -> Result<String, HyxeError> + Send + 'static {
        let (expect_response, eid) = {
            if on_response_received.is_some() {
                (true, Some(packet.get_eid().unwrap_or(generate_rand_u64())))
            } else {
                (false, None)
            }
        };
        remote.clone().execute(send_packet_async(remote, packet, expect_response, Constants::TIMEOUT, eid, on_response_received).then(|res| { Ok(()) })).unwrap();
    }

    /**
        This function acquires the send handle
    */
    pub fn connect_to_local_sockets(&mut self) -> bool {
        let mut count = 0;
        let count_needed = (self.port_end - self.port_start) as usize + self.aux_ports.len();
        let mut initial = Instant::now();

        let mut tmp_map: HashMap<u16, bool> = HashMap::new();

        for port in self.port_start..self.port_end {
            tmp_map.insert(port, false);
        }

        for port in self.aux_ports.iter() {
            tmp_map.insert(*port, false);
        }

        while (initial.elapsed().as_millis() as usize) < Constants::TIMEOUT {
            for port in self.port_start..self.port_end {
                if !tmp_map.get(&port).unwrap() {
                    if let Some(sender) = SocketHandler::acquire_sender(&self.ip_to, &port) {
                        //self.connections.lock().insert(port, sender);
                        tmp_map.insert(port, true);
                        count += 1;
                    }
                }
            }

            for port in self.aux_ports.iter() {
                if !tmp_map.get(&port).unwrap() {
                    if let Some(sender) = SocketHandler::acquire_sender(&self.ip_to, &port) {
                        //self.connections.lock().insert(*port, sender);
                        tmp_map.insert(*port, true);
                        count += 1;
                    }
                }
            }

            //println!("We are at count {} / {}", count, count_needed);
            if count == count_needed {
                self.sockets_are_alive = true;
                return true;
            }
        }
        eprintln!("[BridgeHandler] Unable to connect to local sockets!");

        false
    }


    pub fn sockets_are_alive(&self) -> bool {
        self.sockets_are_alive
    }

    pub fn set_connected(&mut self, connected: bool) {
        self.sockets_are_alive = connected;
    }

    pub fn set_can_check(&mut self, value: bool) {
        self.can_check = value;
    }

    pub fn get_linear_ports(&self) -> &Vec<u16> {
        &self.aux_ports
    }

    pub fn connected_to_peer(&self) -> &bool {
        &self.connected_to_peer
    }

    pub fn reset(&mut self) {
        self.check_connection_fail_count = 0;
        self.check_connection_fail_server_count = 0;
        self.can_check = true;
        self.connected_to_peer = false;
        self.sockets_are_alive = false;
        println!("[BridgeHandler] Bridge has been reset! You must reconnect to local sockets now before any further traffic");
    }

    /// Generally, only HyperLAN clients should have this running
    pub fn initiate_check_connection_worker_async(sid: u128, mut session_checker: SessionChecker, nac: HyxeObject<NetworkAccount>, bridge: Arc<Mutex<BridgeHandler>>, remote: Remote, username: String, password: String) {
        let client_alerter_opt = get_client_alerter();
        if client_alerter_opt.is_none() {
            eprintln!("[SessionHandler] Unable to get GUI Handler! Severe error");
            return;
        }
        let client_alerter = client_alerter_opt.unwrap();
        remote.clone().execute(check_connection_worker_async(sid, session_checker, client_alerter, nac, bridge, remote, username, password)).unwrap();
    }
}

pub fn send_connect_packet_async<'a, F>(bridge: Arc<Mutex<BridgeHandler>>, remote: Remote, nac: HyxeObject<NetworkAccount>, username: String, password: String, security_level: usize, eid: u64, on_packet_received: F) -> impl Future<Item=(), Error=()> + 'a
    where F: Fn(Option<ProcessedInboundPacket>, Remote) -> Result<String, HyxeError> + Send + 'static {
    futures::lazy(move || {
        if bridge.lock().connected_to_peer {
            return Ok(());
        }
        let nac2 = Arc::clone(&nac);
        let nac3 = Arc::clone(&nac);
        let bridge = Arc::clone(&bridge);

        let bridge = bridge.lock();

        let (ip_to, aux_port) = bridge.get_connect_data();

        let drill_version = nac.lock().get_latest_drill_version().unwrap();
        let security_level = SecurityLevel::from_byte(&(security_level as u8)).unwrap();
        nac2.lock().set_security_level(security_level);
        //let eid = nac2.lock().get_hyper_random::<u64>(0 as u64).unwrap();
        let mut packet = PacketGenerator::generate_connect_packet(None, nac3, ip_to, *aux_port, &username, &password, drill_version, eid);
        if let Some(packet) = packet {
            //let expectancy = Expectancy::new(eid, remote.clone(), ExecutableClosure::new(on_packet_received));
            //EXP_QUEUES.lock().insert(eid, expectancy);
            remote.clone().spawn(move |handle|
                Timeout::new(send_packet_async(remote.clone(), packet, true, Constants::TIMEOUT, Some(eid), Some(move |mut packet: Option<ProcessedInboundPacket>, remote: Remote| {
                    println!("[BridgeHandler] Executing");
                    on_packet_received.call((packet, remote));
                    Ok("okay".to_string())
                })).and_then(|packet: Option<ProcessedInboundPacket>| {
                    println!("Got packet? {}", packet.is_some());
                    Ok(())
                }).map_err(|err| { eprintln!("ERR: {}", err) }), Duration::from_millis(Constants::TIMEOUT as u64)).then(|res| {
                    match res {
                        Err(err) => eprintln!("[BridgeHandler] Error"),
                        _ => { println!("RESULT!") }
                    }
                    Ok(())
                })
            );
        }
        Ok(())
    }).map_err(|err: String| {})
}

/// When a wave is sent, eventually the adjacent node will return a response to the local node
pub fn send_wave_async<'a, F: 'static>(remote: Remote, session: HyxeObject<Session>, wave_series: PacketSeriesLayout, ip_to: &'a String, on_wave_received: F) -> impl Future<Item=Option<ProcessedInboundPacket>, Error=HyxeError> + 'a
    where F: Fn(Option<ProcessedInboundPacket>, Remote) -> Result<String, HyxeError> + Send + 'a {
    futures::lazy(move || {
        //We need to dispatch all of the packets in the layout, but first we need to send a PACKET_SERIES_HEADER packet to notify the peer node that it will be receiving a series of packets
        //STEP 1: Create and dispatch PACKET_SERIES_HEADER to peer node
        let mut counter = 0;
        let oid_eid = wave_series.oid_eid.clone();
        let drill_version = wave_series.drill_version.clone();
        let port_start = session.lock().nac.lock().get_port_range();

        if let Some(header_packet) = PacketGenerator::generate_object_header_packet(session, ip_to, oid_eid, wave_series.len() as u64, drill_version) {
            printf_success(format!("[BridgeHandler] Crafted object-header packet; dispatching!"));
            let remote_obj_header = remote.clone();

            ///We add an expectancy to the object, that way the other node can signal this node when it's done processing as a type of ACK
            ///TODO: Ensure the timeout parameter is actually calculated as a function of internet speed && data size! For debug purposes, it is just Constants::TIMEOUT
            remote.execute(send_packet_async(remote_obj_header, header_packet, true, Constants::TIMEOUT, Some(oid_eid), Some(on_wave_received)));

            let remote_column_header = remote_obj_header.clone();
            let single_packet_remote = remote_column_header.clone();
            for (wave_id, packets) in wave_series {
                //Construct packet_column_header & dispatch; then construct all sub_packets and dispatch individually

                if let Some(column_header_packet) = PacketGenerator::generate_column_header_packet(session.clone(), ip_to, wave_id, packets.len() as u16, drill_version) {
                    remote_obj_header.clone().execute(send_packet_async(remote_obj_header, header_packet, true, Constants::TIMEOUT, Some(oid_eid), Some(on_wave_received)));

                    for (src_port, dest_port, payload) in packets {
                        if let Some(singleton_packet) = PacketGenerator::generate_wave_packet(session, (src_port + port_start) as u16, (dest_port + port_start) as u16, ip_to, wave_id, oid_eid, payload, drill_version) {
                            single_packet_remote.execute(send_packet_async(single_packet_remote.clone(), singleton_packet, false, Constants::TIMEOUT, None, None));
                        }
                    }
                }
            }
        }
    })
}

pub fn send_packet_async<'a, F: 'static>(remote: Remote, packet: OutboundPacket, expect_response: bool, timeout: usize, expectancy_value: Option<u64>, on_packet_received: Option<F>) -> impl Future<Item=Option<ProcessedInboundPacket>, Error=HyxeError> + 'a
    where F: Fn(Option<ProcessedInboundPacket>, Remote) -> Result<String, HyxeError> + Send + 'a {
    futures::lazy(move || {
        println!("[BridgeHandler] Sending a packet to {}:{}", &packet.dest_ip, &packet.dest_port);
        //Mutex<HashMap<String, Mutex<HashMap<u16, Arc<Mutex<SegQueue<String>>>>>>>
        if let Some(sender) = SocketHandler::acquire_sender(&packet.dest_ip, &packet.dest_port) {
            let key = format!("{}:{}", &packet.dest_ip, &packet.dest_port);

            /// We encode right before sending the data now, including the HyxeHeader. The underlying KCP header will allow the packet to be parsed across the network
            let msg = base64::encode(packet.data);

            sender.lock().push(msg);
            println!("[BridgeHandler] Sent packet successfully!");

            /// We notify this to push the data from the sender into the socket outbound stream
            Globals::SOCKET_TASKS_INPUT.lock().get(&key).unwrap().lock().notify();

            if let Some(expectancy_value) = expectancy_value {
                if let Some(fx) = on_packet_received {
                    Globals::EXP_QUEUES.lock().insert(eid, Expectancy::new(expectancy_value, false, remote, timeout, ExecutableClosure::new(fx)));
                }
            }
            return Ok(None);
        }
        printf_err(format!("[BridgeHandler] [SEND_PACKET_ASYNC] Unable to acquire sender! Tried to get {}", packet.get_dest_ip()).as_str());
        Ok(None)
    })
}