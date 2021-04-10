/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use core::borrow::{Borrow, BorrowMut};
use std::cell::{RefCell, UnsafeCell};
use std::io::Write;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::ptr::Unique;
use std::sync::Arc;
use std::time::{Duration, Instant};

use atoi::*;
use bytes::BytesMut;
use crossbeam_channel::{Receiver, Sender, unbounded};
use crossbeam_channel::TryRecvError;
use futures::future::{Executor, Future, IntoFuture};
use futures::sink::Sink;
use futures::stream::Stream;
use futures::task::Task;
use hashbrown::HashMap;
use mut_static::MutStatic;
use net2::TcpBuilder;
use parking_lot::Mutex;
use rayon::Scope;
use rayon::str::ParallelString;
use tokio::codec::LinesCodec;
use tokio::io;
use tokio::net::TcpListener;
use tokio::prelude::*;
use tokio::timer::{Delay, Interval};
use tokio::timer::Error;
use tokio_core::io::Framed;
use tokio_core::net::{UdpCodec, UdpSocket};
use tokio_core::reactor::{Handle, Remote};

use hyxe_util::HyxeError;

use crate::bytes::BufMut;
use crate::hyxewave::misc::{Constants, Globals};
use crate::hyxewave::misc::Constants::{*, {MAINFRAME_SERVER_IP, TIMEOUT}, DAEMON_COMMANDS::*};
use crate::hyxewave::misc::Constants::DAEMON_COMMANDS;
use crate::hyxewave::network::BridgeHandler::{BridgeHandler, send_connect_packet_async};
use crate::hyxewave::network::PacketProcessor::PacketSubtype;
use crate::hyxewave::network::session::{*, SessionHandler::ClientSourceType};
use crate::hyxewave::network::session::NetworkAccount;
use crate::Substring;
use crate::tokio_io::AsyncRead;

pub struct GUIConnector {
    sender: Sender<String>,
    //to_receiver
    receiver: Receiver<String>,
    can_run: bool,
    remote: Remote,
    central_bridges: Arc<HashMap<String, Arc<Mutex<BridgeHandler>>>>,
}

impl GUIConnector {
    pub fn new(central_bridge_default: Arc<Mutex<BridgeHandler>>, remote: Remote) {
        let (sender, mut receiver) = unbounded::<String>();
        let mut central_bridges = HashMap::new();
        central_bridges.insert(MAINFRAME_SERVER_IP.to_string(), Arc::clone(&central_bridge_default));

        let central_bridges = Arc::new(central_bridges);

        let mut gui = GUIConnector { sender, receiver, can_run: true, remote, central_bridges };

        if Globals::GUI_CONNECTOR.is_set().unwrap() {
            //on restart, the static may already be set
            *Globals::GUI_CONNECTOR.write().unwrap() = gui;
        } else {
            //on first startup, we must set the field
            Globals::GUI_CONNECTOR.set(gui).unwrap();
        }

        run_gui_connector();
    }

    pub fn shutdown(&mut self) {
        self.can_run = false;
    }

    pub fn send_data_to_gui(&self, data: String) {
        &self.sender.send(data).unwrap();
    }

    pub fn get_gui_send_handle(&self) -> Sender<String> {
        self.sender.clone()
    }
}

pub fn run_gui_connector() {
    let mut obj = Globals::GUI_CONNECTOR.read().unwrap();
    let bridges = Arc::clone(&obj.central_bridges);
    let remote = obj.remote.clone();
    let sender = obj.sender.clone();
    let receiver = obj.receiver.clone();

    remote.clone().spawn(move |h| {
        listen(bridges, remote, sender, receiver).map_err(|mut err| {
            err.printf();
        })
    });
}

pub fn send_to_gui(sender: &Sender<String>, status: &str, sid: u128, data_and_eid: Option<(&str, u64)>) {
    let sender = sender.clone();
    if let Some((data, eid)) = data_and_eid {
        sender.send(format!("[status]{}[/status][sid]{}[/sid][data]{}[/data][eid]{}[/eid]", status, sid, data, eid));
        return;
    }


    sender.send(format!("[status]{}[/status][sid]{}[/sid]", status, sid));
}

pub fn process_data<'a>(bridges: Arc<HashMap<String, Arc<Mutex<BridgeHandler>>>>, remote: Remote, sender: Sender<String>, data: String) -> impl Future<Item=(), Error=()> + 'a {
    futures::lazy(move || {
        println!("[GUI-Daemon] received: {}", data);
        let sender = sender.clone();
        let remote = remote.clone();
        if data.contains("[u]") {
            let cmd_idx_end = data.find("[u]").unwrap();
            let cmd = data[0..cmd_idx_end].to_string().replace("[", "").replace("]", "");
            println!("CMD: {}", cmd);

            match cmd.as_str() {
                DAEMON_COMMANDS::DO_CONNECT => {
                    println!("[Async GUI-Daemon] DAEMON_CMD: DO_CONNECT");
                    //stage 1: Data has been received, check for completeness before sending request to server
                    let blank = "".to_string();
                    let username = data.substring("[u]", "[/u]").unwrap_or(blank.clone());
                    let password = data.substring("[p]", "[/p]").unwrap_or(blank.clone());
                    let central_node = data.substring("[ip]", "[/ip]").unwrap_or(blank.clone());
                    let security_level = atoi::atoi::<usize>(data.substring("[sec]", "[/sec]").unwrap_or(blank.clone()).as_bytes()).unwrap_or(999);
                    let eid = atoi::atoi::<u64>(data.substring("[eid]", "[/eid]").unwrap_or(blank.clone()).as_bytes()).unwrap_or(999);

                    if username.eq(&blank) || password.eq(&blank) || central_node.eq(&blank) || security_level == 999 || eid == 999 {
                        eprintln!("[Async GUI-Daemon] Data contains invalid information; sending DO_CONNECT_FAILURE");
                        send_to_gui(&sender, DAEMON_COMMANDS::DO_CONNECT_FAILURE, 0, Some(("Invalid information provided", eid)));
                        return Ok(());
                    }

                    //stage 2: Data is complete, but now check for its validiity
                    let nac = NetworkAccount::get_nac_by_username(&username);
                    if nac.is_none() {
                        println!("[Async GUI-Daemon] Unable to find NAC for {}", username);
                        send_to_gui(&sender, DAEMON_COMMANDS::DO_CONNECT_FAILURE, 0, Some(("NAC Not found locally", eid)));
                        return Ok(());
                    }

                    let nac = nac.unwrap();

                    //Now, validate password with decrypted password in memory
                    if !nac.lock().validate_password(&password) {
                        eprintln!("[Async GUI-Daemon] Invalid password for {}", username);
                        send_to_gui(&sender, DAEMON_COMMANDS::DO_CONNECT_FAILURE, 0, Some(("Invalid password specified", eid)));
                        return Ok(());
                    }

                    //finally, check that the requested server exists


                    let bridge = bridges.get(&central_node);
                    if bridge.is_none() {
                        eprintln!("[Async GUI-Daemon] Invalid IP for {}", username);
                        send_to_gui(&sender, DAEMON_COMMANDS::DO_CONNECT_FAILURE, 0, Some(("Invalid Server Address Specified", eid)));
                        return Ok(());
                    }

                    let bridge = Arc::clone(bridge.unwrap());
                    let remote = remote.clone();


                    println!("[Async GUI-Daemon] Sending login request");
                    remote.spawn(move |handle| {
                        let bridge = Arc::clone(&bridge);
                        let sender = sender.clone();
                        let remote = handle.remote().clone();

                        send_connect_packet_async(bridge, remote, Arc::clone(&nac), username, password, security_level, eid, move |mut packet, rmt| {
                            if let Some(packet) = packet {
                                println!("[Async GUI-Daemon] Packet received! Evaluating final step...");
                                if packet.get_subtype() == &PacketSubtype::CONNECT_SUCCESS {
                                    println!("[Async GUI-Daemon] Connect Success! Sending alert to GUI");
                                    let peer_ip = packet.get_src_ip().clone();
                                    if let Some(session) = SessionHandler::StateTransfer::on_login_success_client(ClientSourceType::GUI, Arc::clone(&nac), rmt, peer_ip) {
                                        let sid = session.lock().sid;
                                        println!("[Async GUI-Daemon] Obtained SID {}", sid);
                                        send_to_gui(&sender, DAEMON_COMMANDS::DO_CONNECT_SUCCESS, sid, Some(("", eid)));
                                    }
                                }
                            } else {
                                eprintln!("[Async GUI-Daemon] Empty packet => timeout reached");
                                send_to_gui(&sender, DAEMON_COMMANDS::DO_CONNECT_FAILURE, 0, Some(("Timeout connecting to server", eid)))
                            }

                            Ok("okay".to_string())
                        })
                    });
                    //background_core.run(
                    //check_connection_worker_async(nac, central_bridge,bg_remote3, "tbraun96@gmail.com".to_string(), "mrmoney10".to_string()).map_err(|err| {eprintln!("Error occured! {:?}", err)})).unwrap();
                }
                DAEMON_COMMANDS::DO_CONNECT_SUCCESS => {}
                DAEMON_COMMANDS::DO_CONNECT_FAILURE => {}
                DAEMON_COMMANDS::DO_DISCONNECT => {}
                DAEMON_COMMANDS::DO_DISCONNECT_SUCCESS => {}
                DAEMON_COMMANDS::DO_DISCONNECT_FAILURE => {}
                DAEMON_COMMANDS::DO_SEND_MESSAGE => {}
                DAEMON_COMMANDS::DO_SEND_MESSAGE_SUCCESS => {}
                DAEMON_COMMANDS::DO_SEND_MESSAGE_FAILURE => {}
                DAEMON_COMMANDS::DO_SEND_FILE => {}
                DAEMON_COMMANDS::DO_SEND_FILE_SUCCESS => {}
                DAEMON_COMMANDS::DO_SEND_FILE_FAILURE => {}
                _ => { eprintln!("[GUI Daemon] Invalid command: {}", cmd) }
            }
            //&sender.clone().send(format!("You said: {}", cmd));
        }
        Ok(())
    }).map_err(|err: std::io::Error| {})
}

pub fn listen<'a>(bridges: Arc<HashMap<String, Arc<Mutex<BridgeHandler>>>>, remote: Remote, sender: Sender<String>, receiver: Receiver<String>) -> impl Future<Item=(), Error=HyxeError> + 'a {
    let addr_daemon = format!("{}:{}", "127.0.0.1", LOOPBACK_PORT);
    let addr_daemon = addr_daemon.parse::<SocketAddr>().unwrap();

    let handle = remote.handle().unwrap();

    let socket = UdpSocket::bind(&addr_daemon, &handle).unwrap();
    let sck = Arc::new(Mutex::new(socket));
    let sck0 = Arc::clone(&sck);
    let listener = UdpListener(sck, receiver);
    println!("[Async GUI-Daemon] listening on: {}", &addr_daemon);

    let addr_to = Arc::new(Mutex::new(Vec::new()));
    let cxn_exists = false;

    let sender_svc = sender.clone();
    //let bridges = Arc::new(Mutex::new(bridges));

    //remote.execute();

    listener.from_err().for_each(move |(inbound_packet, outbound_packet)| {
        if let Some((inbound_packet, addr)) = inbound_packet {
            if addr.ip().is_loopback() {
                println!("[Async GUI] Received an inbound packet from daemon {} with data {}", inbound_packet, addr.to_string());
                if !&cxn_exists {
                    Arc::clone(&addr_to).lock().insert(0, addr);
                }
                //sender.send(inbound_packet).expect("Unable to send message to daemon...");
                remote.clone().execute(process_data(Arc::clone(&bridges), remote.clone(), sender.clone(), inbound_packet));
            }
        }

        if let Some(outbound_packet) = outbound_packet {
            if outbound_packet.eq("SYS_SHUTDOWN") {
                return HyxeError::throw("[Async GUI-Daemon] System signalled to shut down");
            }

            println!("[Async GUI-Daemon] Received an outbound request...");
            let obj = Arc::clone(&addr_to);
            if !obj.lock().is_empty() {
                match sck0.lock().send_to(outbound_packet.as_bytes(), obj.lock().get(0).unwrap()) {
                    Ok(len) => { println!("SEND success"); }
                    _ => {}
                }
            }
        }

        Ok(())
    }).join(Interval::new(Instant::now(), Duration::from_millis(75)).from_err().for_each(move |instant| {
        if !Globals::system_engaged() {
            return HyxeError::throw("[GUI Connector] System signalled to shut down");
        }

        if !Globals::GUI_CONN_UDP_TASK.lock().is_empty() {
            Globals::GUI_CONN_UDP_TASK.lock()[0].notify();
        }

        Ok(())
    }).map_err(move |mut err: HyxeError| {
        sender_svc.send("SYS_SHUTDOWN".to_string()).unwrap();
        err.printf()
    })).then(|result: Result<((), ()), HyxeError>| {
        HyxeError::throw("[GUI Connector] System shutting down")
    })
}

pub struct UdpListener(Arc<Mutex<UdpSocket>>, Receiver<String>);

impl Stream for UdpListener {
    type Item = (Option<(String, SocketAddr)>, Option<String>);
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if Globals::GUI_CONN_UDP_TASK.lock().is_empty() {
            Globals::GUI_CONN_UDP_TASK.lock().push(task::current());
        }

        let mut buf = &mut [0 as u8; 64000];
        match self.0.lock().recv_from(buf) {
            Ok((len, addr)) => if len != 0 {
                return Ok(Async::Ready(Some((Some((String::from_utf8_lossy(&buf[0..len]).to_string(), addr)), None))));
            },
            _ => {}
        }

        if let Ok(result) = self.1.try_recv() {
            return Ok(Async::Ready(Some((None, Some(result)))));
        }

        return Ok(Async::NotReady);
    }
}


pub fn get_client_alerter() -> Option<Sender<String>> {
    Some(Globals::GUI_CONNECTOR.read().unwrap().get_gui_send_handle())
}