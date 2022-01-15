/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use futures::stream::Stream;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures_mpmc::array::{array, Receiver, Sender};
use hashbrown::HashMap;
use parking_lot::Mutex;
use rayon::Scope;
use tokio::prelude::Future;
use tokio::prelude::future::Executor;
use tokio_core::reactor::{Core, Handle, Remote};

use hyxe_util::HyxeError;
use tokio_kcp::KcpSessionManager;

use crate::hyxewave::misc::Constants;
use crate::hyxewave::misc::Globals::MAIN_CONNECTION_REQUEST_PIPE;
use crate::hyxewave::misc::Utility::{printf_err, printf_success};
use crate::hyxewave::network::Packet::Packet;
use crate::hyxewave::network::SocketHandler;
use crate::hyxewave::network::StageFlowHandler::StageHousing;

/**
    The purpose of this is to replace the deprecated WaveformListener because it was geometrically unorderly (metaphorically).
    In the case of the server, nothing much needs to change: execute all 20 + 2 SocketListener Futures, and use MPSC to forward the packets
    into a two sinks (one for linear packets, one for wave packets).

    As for the client, we must consider that, at any time, one of the connections may be interrupted. As such, the connection must be restarted
    if a reconnection is desired.

    For both server and client cases, the async cores and cells must NOT BE TRANSFERRED BETWEEN THREADS. This is why tubing is needed, because it
    can cancel a future on command that it is joined() or selected() with (pref select).

    As such, for both server and client cases, the SocketHandler::connect() || SocketHandler::listen() must be called and ran on a single function.
    This function should add a sender to
*/

pub struct ConnectionHandler {
    /// We want multithreaded access to these tubes "just-in-case"
    pub tube_senders: Arc<Mutex<HashMap<String, Vec<UnboundedSender<String>>>>>,
    pub ports: Vec<u16>,

    /// We need these to push the information from the sockets to stage1++
    pub stage0_tx_wave: UnboundedSender<Packet>,
    pub stage0_tx_linear: UnboundedSender<Packet>,
    pub kcp_manager: Option<KcpSessionManager>,
}

impl ConnectionHandler {
    /// We need the senders in order to push packets from the sockets (stage0) to stage1++
    pub fn new(port_start: u16, port_end: u16, aux_ports: Vec<u16>, stage0_tx_wave: UnboundedSender<Packet>, stage0_tx_linear: UnboundedSender<Packet>) -> Self {
        let mut ports = vec!();

        for port in port_start..port_end {
            ports.push(port);
        }

        for port in aux_ports.iter() {
            ports.push(*port);
        }

        Self { tube_senders: Arc::new(Mutex::new(HashMap::new())), ports, stage0_tx_wave, stage0_tx_linear, kcp_manager: None }
    }

    pub fn stop_connection(&mut self, peer_addr: String) -> Result<(), HyxeError> {
        if let Some(tubes) = self.tube_senders.lock().get(&peer_addr) {
            let count_needed = tubes.len();
            let mut count = 0;
            for tube in tubes {
                /// We do this to shutdown the futures which are listening for data from the sockets
                tube.unbounded_send("DISCONNECT".to_string()).and_then(|r_| {
                    count += 1;
                    Ok(())
                });
            }

            if count == count_needed {
                printf_success(format!("[ConnectionHandler] Stopped all futures; now, going to alert KCP Manager to shutdown any possibly remaining streams to {}!", &peer_addr));
                self.kcp_manager.clone().unwrap().stop();
                self.kcp_manager = None;

                return Ok(());
            }

            return HyxeError::throw("[ConnectionHandler] Unable to send information through all the tubes. Cannot disconnect!");
        }

        HyxeError::throw("[ConnectionHandler] Invalid IP specified (not found). Cannot disconnect!")
    }

    pub fn connect_to(cxn_handler: Arc<Mutex<ConnectionHandler>>, peer_addr: String) -> Result<(), HyxeError> {
        connect_to(cxn_handler, peer_addr)
    }
}

/// This is for the client! It allows multiple connections
pub fn connect_to(cxn_handler: Arc<Mutex<ConnectionHandler>>, peer_addr: String) -> Result<(), HyxeError> {
    if cxn_handler.lock().tube_senders.lock().contains_key(&peer_addr) {
        printf_success(format!("[ConnectionHandler] Dataset already exists; clearing information!"));
        std::mem::drop(cxn_handler.lock().tube_senders.lock().remove_entry(&peer_addr).unwrap());
    }

    rayon::spawn(move || {
        let mut core = Core::new().unwrap();

        let handle = core.handle().clone();
        let remote = core.remote();

        let mut kcp_sess = KcpSessionManager::new(&handle.clone(), peer_addr.clone()).unwrap();
        cxn_handler.lock().kcp_manager = Some(kcp_sess.clone());

        let mut tubes_tx = vec!();
        let mut futures_arr = vec!();

        let ports = cxn_handler.lock().ports.clone();

        for port in ports {
            let (tube_tx, tube_rx) = unbounded::<String>();
            let addr = SocketAddr::new(IpAddr::from_str(peer_addr.as_str()).unwrap(), port);
            let handle = handle.clone();
            let sender_tx_wave = cxn_handler.lock().stage0_tx_wave.clone();
            let sender_tx_linear = cxn_handler.lock().stage0_tx_linear.clone();
            tubes_tx.push(tube_tx);
            futures_arr.push(SocketHandler::connect(port, addr, handle, sender_tx_wave, sender_tx_linear, tube_rx, kcp_sess.clone()));
        }

        cxn_handler.lock().tube_senders.lock().insert(peer_addr.clone(), tubes_tx);

        let join_all = futures::future::join_all(futures_arr);
        core.run(join_all.then(|res| Ok(())).map_err(|err: HyxeError| {})).unwrap();
    });

    Ok(())
}

/// This is for the server!
pub fn listen(cxn_handler: Arc<Mutex<ConnectionHandler>>) -> Result<(), HyxeError> {
    if cxn_handler.lock().tube_senders.lock().contains_key(Constants::LOCALHOST) {
        return HyxeError::throw(format!("Connection to {} already exists!", Constants::LOCALHOST).as_str());
    }

    rayon::spawn(move || {
        let mut core = Core::new().unwrap();

        let handle = core.handle().clone();
        let remote = core.remote();

        let mut tubes_tx = vec!();
        let mut futures_arr = vec!();

        let ports = cxn_handler.lock().ports.clone();

        for port in ports {
            let (tube_tx, tube_rx) = unbounded::<String>();
            let handle = handle.clone();
            let sender_tx_wave = cxn_handler.lock().stage0_tx_wave.clone();
            let sender_tx_linear = cxn_handler.lock().stage0_tx_linear.clone();
            tubes_tx.push(tube_tx);
            //port: u16, handle: Handle,tx_wave_to_processing: futures::sync::mpsc::UnboundedSender<Packet>, tx_linear_to_processing: futures::sync::mpsc::UnboundedSender<Packet>, tube_rx: UnboundedReceiver<String>
            futures_arr.push(SocketHandler::listen(port, handle, sender_tx_wave, sender_tx_linear, tube_rx));
        }

        cxn_handler.lock().tube_senders.lock().insert(Constants::LOCALHOST.to_string(), tubes_tx);

        let join_all = futures::future::join_all(futures_arr);
        core.run(join_all.then(|res| Ok(())).map_err(|err: HyxeError| {})).unwrap();
    });

    Ok(())
}

/// This allows the core to block its containing rayon::scope, waiting for all futures to finish. In either case
/// of either server or client, it listens to Globals::MAIN_CONNECTION_REQUEST_PIPE, blocking until a HALT signal
/// or RESTART signal is given.
/// `core_communicator` needs to be tied to Globals::MAIN_CONNECTION_REQUEST_PIPE, that way signals can be sent to it
pub fn core_blocker(cxn_handler: Arc<Mutex<ConnectionHandler>>, core_communicator_rx: Receiver<String>) {
    /// By running the core, we not only block hereon, but we also run all the other futures added to it

    core_communicator_rx.from_err::<HyxeError>().for_each(move |signal| {
        if signal.as_str().contains("CONNECT") {
            let server_addr = signal.replace("CONNECT", "");
            printf_success(format!("[ConnectionHandler] Received CONNECT signal [{}]", server_addr));
            connect_to(Arc::clone(&cxn_handler), server_addr);
            Ok(())
        } else if signal.as_str().contains("LISTEN") {
            printf_success(format!("[ConnectionHandler] Received LISTEN signal; beginning socket listeners!"));
            listen(Arc::clone(&cxn_handler));
            Ok(())
        } else if signal.as_str().contains("STOP") {
            HyxeError::throw("STOPPING CONNECTION HANDLER")
        } else {
            printf_err(format!("[ConnectionHandler] Received an unknown signal: {}", signal).as_str());
            Ok(())
        }
    }).map_err(|mut err| err.printf()).wait();
}

