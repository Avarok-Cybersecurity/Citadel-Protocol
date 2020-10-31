/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::prelude::Async;
use tokio_core::reactor::Remote;

use hyxe_util::HyxeError;

use crate::hyxewave::encrypt::WaveFormGenerator;
use crate::hyxewave::network::Packet::Packet;
use crate::hyxewave::network::WaveformListener::WaveformListener;
use crate::prelude::HyxeObject;
use crate::SecurityLevel;

use self::super::AsyncHandler::AsyncHandler;
use self::super::super::network::session::NetworkAccount::NetworkAccount;

pub struct Communicator(pub HyxeObject<NetworkAccount>, pub Arc<AsyncHandler>);

pub struct Response(pub String);

///Important: The communicator layer is NOT responsible for setting the drill version... the lower-level async manager DOES
impl Communicator {
    pub fn new(session_id: &u128) -> Option<Self> {
        let async_handler = AsyncHandler::new(session_id);

        if async_handler.is_none() {
            return None;
        }
        let async_handler = async_handler.unwrap();
        let nac = async_handler.get_nac();
        Some(Self(nac, Arc::new(async_handler)))
    }

    fn get_nac(&self) -> HyxeObject<NetworkAccount> {
        Arc::clone(&self.0)
    }

    fn get_async_handler(&self) -> Arc<AsyncHandler> { Arc::clone(&self.1) }

    ///`data`: input unencrypted data only!
    /// This function is used mostly to signal and communicate directly to the central server
    pub fn send_message_central<F>(&self, data: Vec<u8>, on_message_received: Option<F>) where
        F: Fn(Option<ProcessedInboundPacket>, Remote) -> Result<String, HyxeError> + Send + 'static {
        let nac = self.get_nac();
        let mut nac = nac.lock();
        let security_level = (&mut nac).get_security_level();

        let nac2 = Arc::clone(&self.get_nac());
        let mut nac2 = nac2.lock();
        let dest_ip = nac2.get_central_node_ip().clone();

        self.get_async_handler().send_coms_message_async(data, dest_ip, on_message_received);
    }

    ///`cid` We only need to provide the cid here because the server contains the information of the mapping from cid to ip_addr
    pub fn send_message_hyperlan(&self, data: Vec<u8>, cid: u64, expect_response: bool, on_message_received: Option<F>) where
        F: Fn(Option<ProcessedInboundPacket>, Remote) -> Result<String, HyxeError> + Send + 'static {
        WaveFormGenerator::create_linear_mapping()
    }

    pub fn send_message_hyperwan(&self, data: Vec<u8>, ip_to: &String)
}

impl Response {
    pub fn get_message(self) -> String {
        self.0.to_owned()
    }
}



