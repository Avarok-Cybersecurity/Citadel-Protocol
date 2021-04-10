/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */


//The purpose of this file is to connect with the central mainframe server or HyperWAN server and register for a NetworkAccount

//The other purpose is to retrieve an unused NID for a local node. This is a cheap operation, and no requirements are needed
//unless the config is set to WHITELIST_IP_ONLY by the server admin. The whitelist is a local text file in %HYXE_HOME%/cfg/Server.conf


use std::net::{IpAddr, Shutdown, SocketAddr, SocketAddrV6};

use futures::stream::Stream;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::Future;

use hyxe_util::HyxeError;

use crate::hyxewave::misc::Constants::{LOCALHOST, REGISTRATION_PORT};
use crate::hyxewave::misc::Utility::printf_err;

pub fn run_registration_server() -> impl Future<Item=(), Error=HyxeError> {
    let local_addr = SocketAddr::new(IpAddr::from_str(LOCALHOST).unwrap(), REGISTRATION_PORT);
    let server = TcpListener::bind(&local_addr);

    if server.is_err() {
        HyxeError::throw("[Registration Server] Unable to bind to local address!");
    }

    let server = server.unwrap();

    server.incoming().for_each(move |cxn| {
        println!("[Registration Server] Connection with {} established!");
        if !server_is_whitelisted(cxn.local_addr().unwrap()) {
            printf_err("[Registration Server] Peer connection {} denied due to nonexistence on whitelist");
            cxn.shutdown(Shutdown::Both)?;
            Ok(())
        } else {
            let (rx, tx) = cxn.split();
            let mut framed = tokio_codec::Framed::new(cxn, tokio_codec::LinesCodec::new());

            let (sink, stream) = framed.split();

            stream.fo
        }
    })
}

pub fn get_available_nid(server_addr: SocketAddr) -> impl Future<Item=u64, Error=HyxeError> {
    TcpStream::connect(&server_addr).and_then(move |cxn| {}).map_err(|mut err| err.printf())
}

pub fn server_is_whitelisted(peer_addr: SocketAddr) -> bool {
    true
}