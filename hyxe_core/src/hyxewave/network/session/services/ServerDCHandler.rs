/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::alloc::Global;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::{Executor, Future};
use futures::future::FutureResult;
use futures::stream::Stream;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use lazy_static::LazyStatic;
use multimap::MultiMap;
use parking_lot::Mutex;
use tokio::io::ErrorKind;
use tokio::prelude::future;
use tokio::runtime::Runtime;
use tokio::timer::Interval;
use tokio_core::reactor::{Core, Remote};

use hyxe_util::HyxeError;

use crate::hyxewave::misc::Constants;
use crate::hyxewave::misc::Globals;
use crate::hyxewave::misc::Utility::printf_err;
use crate::hyxewave::network::ConnectionHandler::ConnectionHandler;
use crate::hyxewave::network::HyperNode;
use crate::hyxewave::network::session::NetworkAccount::NetworkAccount;
use crate::hyxewave::network::session::SessionHandler::{Session, SessionChecker};
use crate::hyxewave::network::session::SessionHandler;

/**
    This is a relatively unconditional service; it will run without the bounds of normal services tied to session. Why?
    Because all services shutdown when a session ends, and this program is meant to recover the cxn when the session ends.
    Thus, it must outlive normal sessions. [Technical difference between service and this service: there does not exist a
    take_while predicate in the future]

    Causal chain: Server DC's, client fails to connect. Server then re-opens. Client then sends a message, but the client's
    conversation is old. The server recognizes this, and sends a DO_EMERGENCY_RECONNECT signal. The client receives this message,
    but the underlying sender is not guaranteed to receive the message (emergency signal is sent via a connectionless state). We don't know if this is a valid emergency signal.
    What if the signal was sent via DDOS attack? this would overwhelm this client with continually restarting the program. Therefore,
    we must check to see if there was recently a session that closed that matches the IP in the emergency signal. If so, then we can RESTART
    this client and re-instantiate all futures, connections, etc. Any other connections/downloads/transfers to other mainframe servers will be interrupted...
    However, the system will recover those connections. TODO: implement a pause() function which signals any other concurrent connections to pause
    any transfers and expect to continue once the system re-connects. The session will need to remain valid during this time.
*/

pub fn dc_handler<T>(hNode: Arc<Mutex<T>>, remote: Remote) -> impl Future<Item=(), Error=HyxeError> where T: HyperNode {
    let remote0 = remote.clone();
    let (sender, receiver) = unbounded::<String>();

    tokio_kcp::KCP_TO_HYXEWAVE_TUBE.set(sender);
    //Set the sender that way the KCP system can notify us of a possible disconnect

    receiver.from_err().for_each(move |signal| {
        if signal.contains("DO_RECONNECT") {
            //now, check the reconnections_requested memory for servers that need reconnection (loop through all possible)
            let server_addr = signal.replace("DO_RECONNECT", "");
            printf_err(format!("[ServerDCHandler] KCP module signalled that a reconnection is needed for {}. Checking local sessions...", &server_addr).as_str());
            for session in SessionHandler::get_sessions() {
                if session.lock().get_peer_ip().eq(&server_addr) {
                    printf_err(format!("[ServerDCHandler] We found a match! Checking to see if the match is possibly_disconnected with {}", server_addr).as_str());
                    if session.lock().session_is_possibly_dead() {
                        printf_err(format!("[ServerDCHandler] VALID emergency signal received. Now, signalling system to restart connection to {}", server_addr).as_str());
                        //TODO:: figure out the restart mechanism
                        /// MUST use connection handler! <==
                        return hNode.lock().close_connection_to(server_addr.clone());
                    }
                }
            }

            printf_err(format!("[ServerDCHandler] Received an emergency signal, BUT no sessions exist. Restarting connection to central server {}", Constants::MAINFRAME_SERVER_IP.to_string()).as_str());
            //if is valid
            if let Some(cxn_handler) = hNode.lock().get_connection_handler() {
                /// The connect_to function, keep-in-mind, instantiates its own async core!
                return ConnectionHandler::connect_to(cxn_handler, Constants::MAINFRAME_SERVER_IP.to_string());
            } else {
                printf_err("[ServerDCHandler] Unable to get connection handler! Unable to reconnect! Shutting down for safety");
                std::process::exit(-1);
            }
        }

        Ok(()) //no need to restart
    }).map_err(|mut err: HyxeError| { err.printf() })
}