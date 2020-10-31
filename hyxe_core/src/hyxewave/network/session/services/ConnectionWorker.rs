/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam::{Receiver, Sender};
use crossterm::Color;
use futures::stream::Stream;
use parking_lot::Mutex;
use tokio::prelude::Future;
use tokio::timer::Interval;
use tokio_core::reactor::Remote;

use hyxe_util::HyxeError;

use crate::hyxewave::misc::Constants;
use crate::hyxewave::misc::Globals;
use crate::hyxewave::misc::Utility::{printf, printf_err};
use crate::hyxewave::misc::Utility::generate_rand_u64;
use crate::hyxewave::network::BridgeHandler::BridgeHandler;
use crate::hyxewave::network::BridgeHandler::send_packet_async;
use crate::hyxewave::network::ConnectionHandler::ConnectionHandler;
use crate::hyxewave::network::GUIConnector::send_to_gui;
use crate::hyxewave::network::Packet::{Packet, ProcessedInboundPacket};
use crate::hyxewave::network::PacketGenerator;
use crate::hyxewave::network::PacketProcessor::PacketSubtype;
use crate::hyxewave::network::session::NetworkAccount::NetworkAccount;
use crate::hyxewave::network::session::SessionHandler::get_session;
use crate::hyxewave::network::session::SessionHandler::Session;
use crate::hyxewave::network::session::SessionHandler::SessionChecker;

pub fn check_connection_worker_async_server<'a>(mut checker: SessionChecker, receiver: Receiver<String>, bridge: Arc<Mutex<BridgeHandler>>, session: HyxeObject<Session>, remote: Remote) -> impl Future<Item=(), Error=()> + 'a {
    Interval::new(Instant::now(), Duration::from_millis(Constants::TIMEOUT as u64)).take_while(move |instant| {
        checker.execute(remote.clone())
    }).for_each(move |instant| {
        let bridge = Arc::clone(&bridge);
        if let Ok(ping) = receiver.try_recv() {
            println!("[BridgeHandler] check_connection_worker_async_server: ping received! Keeping the bridge open!");
            bridge.lock().sockets_are_alive = true;
            bridge.lock().connected_to_peer = true;
            bridge.lock().check_connection_fail_server_count = 0;
        } else {
            eprintln!("[BridgeHandler] check_connection_worker_async_server: no ping received in past <= 3000ms. Marking the bridge as closed");
            let mut bridge = bridge.lock();
            bridge.check_connection_fail_server_count += 1;
            if bridge.check_connection_fail_server_count >= Constants::MAX_PING_FAILS {
                let sid = session.lock().sid;
                let peer_ip = session.lock().peer_ip.clone();
                bridge.reset();
                eprintln!("[BridgeHandler] The bridge has been down for a sufficiently long time; killing session {}", sid);
                match session.lock().kill_session(&peer_ip) {
                    true => println!("[BridgeHandler] SLAYED session {}", sid),
                    _ => eprintln!("[BridgeHandler] SEVERE ERROR! Unable to kill session {}", sid)
                }
            }
            bridge.connected_to_peer = false;
        }
        Ok(())
    }).then(|res| { Ok(()) })
}

pub fn check_connection_worker_async<'a>(sid: u128, mut checker: SessionChecker, gui_sender: Sender<String>, nac: HyxeObject<NetworkAccount>, bridge: Arc<Mutex<BridgeHandler>>, remote: Remote, username: String, password: String) -> impl Future<Item=(), Error=()> + 'a {
    let username = username.clone();
    let password = password.clone();
    let remote = remote.clone();
    let remote2 = remote.clone();

    let peer_addr = bridge.lock().ip_to.clone();

    let session = checker.session_to_observe.clone();

    //let mut checker = Arc::new(Mutex::new(checker));
    bridge.lock().set_can_check(true); //allow checking from the BridgeHandler-side
    Interval::new(Instant::now(), Duration::from_millis(1000)).take_while(move |instant| {
        checker.execute(remote.clone())
    }).for_each(move |instant| {
        let peer_addr = peer_addr.clone();
        let can_check = bridge.lock().can_check;
        let gui_sender = gui_sender.clone();
        if can_check {
            bridge.lock().can_check = false;
            //let username = Arc::clone(&username);
            //let password = Arc::clone(&password);

            //let map = Arc::clone(&bridge.lock().connections);
            let banner = format!("[BridgeHandler t={}ms] Checking connection with {}", Globals::get_runtime_ns() * 1000000, bridge.lock().ip_to);
            printf(banner.as_str(), Color::Green, Color::Black, true);
            if let Some(port) = bridge.lock().aux_ports.get(0) {
                //TODO: implement drill-version subsystem
                let drill_version = 0;
                let eid = generate_rand_u64();
                let packet = PacketGenerator::generate_connect_packet(Some(Arc::clone(&session)), Arc::clone(&nac), peer_addr, *port, &username, &password, drill_version, eid.clone());
                if let Some(packet) = packet {
                    let packet = packet;
                    let bridge = Arc::clone(&bridge);
                    let bridge2 = Arc::clone(&bridge);

                    let remote2 = remote2.clone();
                    let remote3 = remote2.clone();
                    remote2.clone().spawn(move |handle| {
                        let bridge = Arc::clone(&bridge);

                        println!("[BridgeHandler] About to send_packet_async");
                        handle.spawn(send_packet_async(remote3, packet, true, Some(eid), Some(move |mut packet: Option<ProcessedInboundPacket>, remote: Remote| {
                            let peer_addr = peer_addr.clone();
                            if let Some(packet) = packet {
                                if packet.get_subtype() == &PacketSubtype::CONNECT_SUCCESS {
                                    println!("[ConnectionWorker] Connect success! Allowing traffic across the bridge...");
                                    bridge.lock().sockets_are_alive = true;
                                    bridge.lock().connected_to_peer = true;
                                    send_to_gui(&gui_sender, Constants::DAEMON_COMMANDS::DO_KEEP_ALIVE_SUCCESS, sid, None);
                                }
                                //TODO:: Notify main system to allow communications
                                bridge.lock().set_can_check(true);
                                bridge.lock().check_connection_fail_count = 0 as usize;
                            } else {
                                crate::hyxe_util::printf_err("[ConnectionWorker] We did not receive a response from the server. Marking connection as closed and reconnecting!");
                                bridge.lock().connected_to_peer = false;
                                /// Step 1: Prepare for reconnection
                                let cxn_handler = Globals::get_connection_handler().unwrap();
                                let stop_ok = cxn_handler.lock().stop_connection(peer_addr.clone()).is_ok();

                                if !stop_ok {
                                    printf_err(format!("[ConnectionWorker] Unable to stop connection to {}. Aborting process of reconnection", &peer_addr).as_str());
                                    return Ok("err".to_string());
                                }
                                ConnectionHandler::connect_to(cxn_handler.clone(), peer_addr.clone());
                            }

                            Ok("okay".to_string())
                        })).and_then(|p| { Ok(()) }).map_err(|err| { eprintln!("ERR! {:#?}", err) }));
                        Ok(())
                    })
                } else {
                    eprintln!("[ConnectionHandler] Unable to generate packet. Please check your configuration");
                }
            } else {
                println!("[ConnectionHandler] No auxiliary ports defined! Exiting");
                std::process::exit(-1);
            }
        } else {
            let bridge = Arc::clone(&bridge);
            if bridge.lock().check_connection_fail_count == 3 {
                //eprintln!("[BridgeHandler] Unable to connect, please check your internet connection");
                send_to_gui(&gui_sender, Constants::DAEMON_COMMANDS::DO_KEEP_ALIVE_FAILURE, sid, None);
                bridge.lock().connected_to_peer = false;
                get_session(&sid).unwrap().lock().kill_inner_service(Constants::SERVICES::CONNECTION_WORKER);
                return Ok(());
            } else {
                bridge.lock().check_connection_fail_count += 1;
                //eprintln!("[BridgeHandler] Checker already in progress...");
            }
        }

        Ok(())
    }).then(|E| Ok(())).map_err(|mut err: HyxeError| { err.printf(); })
}