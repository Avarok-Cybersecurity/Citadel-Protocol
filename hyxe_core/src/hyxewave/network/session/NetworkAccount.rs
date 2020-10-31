/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use core::borrow::BorrowMut;
use std::cell::RefCell;
use std::sync::{Arc, RwLock};

use crossterm::Color;
use hashbrown::HashMap;
use parking_lot::Mutex;
use secstr::{SecStr, SecVec};
use serde_derive::{Deserialize, Serialize};
use tokio::prelude::Future;
use tokio_core::reactor::Remote;

use combine::stream::Range;
use hyxe_util::HyxeError;

use crate::{HyxeObject, SecurityLevel};
use crate::hyxewave::encrypt::Drill::{Drill, Toolset};
use crate::hyxewave::encrypt::Drill::HyperRandom;
use crate::hyxewave::encrypt::HyCryptAF::LinearHycryptor;
use crate::hyxewave::encrypt::PacketIDSeries::PacketIDSeries;
use crate::hyxewave::filesystem::HyxeFile::HyxeFile;
use crate::hyxewave::misc::Constants;
use crate::hyxewave::misc::Globals;
use crate::hyxewave::misc::Utility::*;
use crate::hyxewave::network::BridgeHandler::BridgeHandler;
use crate::hyxewave::network::session::SessionHandler::Session;

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkAccount {
    toolset: Toolset,
    full_name: String,
    pub cid: u64,
    pub username: String,
    central_node_ip: String,

    port_start: u16,
    port_end: u16,
    aux_ports: Vec<u16>,

    #[serde(skip)]
    password_unencrypted: SecVec<u8>,

    on_server: bool,
    attribute_file: HyxeFile,
    encrypted_password_file: HyxeFile,
    has_loaded_password_to_memory: bool,

    default_security_level: SecurityLevel,

    linear_hycryptor: LinearHycryptor,

    #[serde(skip)]
    bridge_handler: Arc<Mutex<BridgeHandler>>,
}

impl NetworkAccount {
    fn create(toolset: Toolset, full_name: String, port_start: u16, port_end: u16, aux_ports: Vec<u16>, username: String, central_node_ip: String, password_unencrypted: String, server_instance: bool) -> Result<Self, HyxeError> {
        let cid = generate_rand_u64() ^ generate_rand_u64() ^ generate_rand_u64();
        let mut password_hyxefile = HyxeFile::new();
        let linear_hycryptor = LinearHycryptor::new();
        password_hyxefile.replace_data(format!("Client: {}", full_name), cid.clone(), &password_unencrypted.clone().into_bytes(), &linear_hycryptor, toolset.get_drill(0).unwrap());
        if !password_hyxefile.save_to_disk() {
            eprintln!("[NAC] Severe error. Unable to write password securely to disk. Aborting");
            return HyxeError::throw("[NetworkAccount] Unable to save password to hard drive! Please check permissions before creating an account. Aborting");
        }

        let password_unencrypted = SecVec::new(password_unencrypted.into_bytes());

        Ok(NetworkAccount {
            toolset,
            full_name,
            cid,
            username,
            central_node_ip: central_node_ip.clone(),
            port_start,
            port_end,
            aux_ports,
            password_unencrypted,
            on_server: server_instance,
            attribute_file: HyxeFile::new(),
            encrypted_password_file: password_hyxefile,
            has_loaded_password_to_memory: false,
            default_security_level: SecurityLevel::HIGH,
            linear_hycryptor: LinearHycryptor::new(),
            bridge_handler: Arc::new(Mutex::new(BridgeHandler::new(central_node_ip.clone(), port_start, port_end, Constants::AUX_PORTS.to_vec(), server_instance))),
        })
    }

    pub fn get_security_level(&self) -> SecurityLevel {
        self.default_security_level.clone()
    }

    pub fn set_security_level(&mut self, level: SecurityLevel) {
        self.default_security_level = level;
    }

    pub fn get_full_name(&self) -> &String {
        &self.full_name
    }

    pub fn get_drill(&self, version: usize) -> Option<HyxeObject<Drill>> {
        self.toolset.get_drill(version)
    }

    pub fn get_central_bridge(&self) -> Arc<Mutex<BridgeHandler>> { Arc::clone(&self.bridge_handler) }

    /*
    pub fn execute_central_bridge_service<'a>(&self, session: HyxeObject<Session>, remote: Remote) {
        let nac = self.get_arc_mutex().unwrap();
        let bridge = self.get_central_bridge();
        let username = self.get_username().clone();
        let password = self.password_unencrypted.clone();
        //nac: HyxeObject<NetworkAccount>, bridge: Arc<Mutex<BridgeHandler>>, remote: Remote, username: String, password: String
        self.get_central_bridge().lock().initiate_check_connection_worker_async(session, nac, bridge, remote, username, password);
    }*/

    pub fn get_message_encryptor(&self) -> &LinearHycryptor { &self.linear_hycryptor }

    pub fn get_central_node_ip(&self) -> &String {
        &self.central_node_ip
    }

    pub fn get_aux_ports(&self) -> &Vec<u16> {
        &self.aux_ports
    }

    pub fn save_nac(&self) {
        let username = self.username.clone();
        let username = username.as_str();
        //TODO: Use real cid instead of username/String
        serialize_nac_to_disk(username, self);
    }

    pub fn get_cid(&self) -> &u64 {
        &self.cid
    }

    pub fn get_username(&self) -> &String {
        &self.username
    }

    pub fn validate_password(&self, password_input: &[u8]) -> bool {
        self.validate_bytes(self.password_unencrypted.unsecure(), password_input)
    }

    fn validate_bytes(&self, arr1: &[u8], arr2: &[u8]) -> bool {
        let len = arr1.len();
        if len != arr2.len() {
            return false;
        }

        for idx in 0..len {
            if *arr1[idx] != *arr2[idx] {
                return false;
            }
        }

        true
    }

    pub fn get_password_hyxefile(&mut self) -> &HyxeFile {
        &self.encrypted_password_file
    }

    pub fn on_deserialize(&mut self, is_server: bool) -> bool {
        let drill_version = self.encrypted_password_file.get_drill_version() as usize;
        let password = self.encrypted_password_file.load_from_disk(self.toolset.get_drill(drill_version).unwrap()).unwrap();
        self.on_server = is_server;
        self.password_unencrypted = SecVec::from(String::from_utf8(password).unwrap().replace(" ", ""));
        self.has_loaded_password_to_memory = true;
        self.bridge_handler = Arc::new(Mutex::new(BridgeHandler::new(self.central_node_ip.clone(), self.port_start, self.port_end, self.aux_ports.clone(), is_server)));

        println!("[NAC-Loader] Succesfully loaded password {} for cid {}", self.password_unencrypted, self.cid);
        true
    }

    pub fn get_latest_drill_version(&self) -> Option<u32> {
        println!("Getting latest drill version!");
        self.toolset.get_latest_drill_version()
    }

    /// username, password (cloned). We make this unsafe for purposes of security
    pub unsafe fn get_credentials(&self) -> Option<(String, String)> {
        let pass_opt = String::from_utf8(self.password_unencrypted.unsecure().to_vec());
        if pass_opt.is_ok() {
            (self.username.clone(), pass_opt.unwrap())
        }
        None
    }

    pub fn get_hyper_random<U: HyperRandom>(&self) -> Option<U> {
        self.toolset.get_rand::<U>()
    }

    pub fn compare_to_nac(&self, ext_cid: &u64) -> bool {
        self.cid == *ext_cid
    }

    pub fn get_toolset(&mut self) -> &mut Toolset {
        &mut self.toolset
    }

    pub fn get_port_range(&self) -> u16 {
        &self.port_end - &self.port_start
    }

    pub fn get_port_combos(&self, drill_version: usize) -> &(Vec<u8>, Vec<u8>) {
        self.get_drill(drill_version).unwrap().get_object().get_port_combos()
    }
}

pub fn generate_account<'a: 'static>(remote: Remote, full_name: &'a str, username: &'a str, central_node_ip: &'a str, password: &'a str, port_start: u16, port_end: u16, aux_ports: &'a [u16]) -> impl Future<Item=NetworkAccount, Error=HyxeError> + 'a {
    Toolset::new_async(remote, port_end - port_start, username.to_string()).and_then(move |toolset| {
        Ok(NetworkAccount::create(toolset, full_name.to_string(), port_start, port_end, aux_ports.to_vec(), username.to_string(), central_node_ip.to_string(), password.to_string(), false))
    }).from_err::<HyxeError>().map_err(|mut err| err.printf())
}

pub fn load_nac(username: &str, is_server: bool) -> Option<HyxeObject<NetworkAccount>> {
    println!("[NAC-Loader] Loading NAC {}", username);
    if let Ok(mut nac) = deserialize_nac_from_disk(username) {
        nac.on_deserialize(is_server);
        let cid = nac.cid.clone();
        let cid2 = cid.clone();
        let hyxe_nac = HyxeObject::new(nac);
        Globals::DHT_NACS.lock().insert(cid, hyxe_nac.clone());
        //(255,105,180
        printf(format!("[NAC-Init] Finished loading NAC {} ({})", cid, username).as_str(), Color::Black, Color::Rgb { r: 255, g: 105, b: 180 }, true);
        return Some(hyxe_nac);
    } else {
        printf(format!("[NAC-Loader] Unable to load NAC {}", username).as_str(), Color::Red, Color::Black, true);
    }
    return None;
}

pub fn load_all_nacs(is_server: bool) {
    load_nac_files(is_server);
}

pub fn get_nac_by_username(username: &String) -> Option<HyxeObject<NetworkAccount>> {
    println!("DHT_SIZE: {}", Globals::DHT_NACS.lock().len());
    for (cid, nac) in Globals::DHT_NACS.lock().iter() {
        if nac.read().username.eq(username) {
            return Some(Arc::clone(&nac));
        }
    }
    None
}

pub fn get_nac(cid: &u64) -> Option<HyxeObject<NetworkAccount>> {
    println!("# of nacs: {}", Globals::DHT_NACS.lock().len());
    if Globals::DHT_NACS.lock().contains_key(cid) {
        return Some(Globals::DHT_NACS.lock().get(cid).unwrap().clone());
    }
    None
}

pub fn get_nac_to_bridge_pair(cid: &u64) -> Option<(HyxeObject<NetworkAccount>, Arc<Mutex<BridgeHandler>>)> {
    if let Some(nac) = get_nac(cid) {
        let bridge = (*nac.lock()).get_central_bridge();
        return Some((nac, bridge));
    }
    None
}

