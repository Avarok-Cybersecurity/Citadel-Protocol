/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */


use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};
/**
    To save time form needing to fetch a new set of hyperandom numbers, this function retrieves the entropy bank
    and updates it if necessary
*/
use futures::future::Future;
use hashbrown::HashMap;

use rayon::prelude::*;
use serde_derive::{Deserialize, Serialize};
use tokio_core::reactor::Remote;

use crate::hyxewave::misc::Constants::{Flags, MAINFRAME_SERVER_IP};
use crate::hyxewave::misc::Utility::{deserialize_drill_from_disk as deserialize, scramble_array};

use crate::hyxewave::network::session::NetworkAccount::NetworkAccount;

use crate::prelude::HyxeObject;
use hyxe_util::result::HyxeError;

pub const PORT_COMBOS_INDEX: u8 = 0;
pub const C_RAND_INDEX: u8 = 1;
pub const K_RAND_INDEX: u8 = 2;
pub const AMPLITUDE_DIFFERENTIALS_KEY_INDEX: u8 = 3;
pub const AMPLITUDE_DIFFERENTIALS_DO_ADD: u8 = 4;
pub const VIRTUAL_TIME_INDEX: u8 = 5;
pub const E_OF_X_START_INDEX: u8 = 6;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Drill {
    low: HashMap<u8, HashMap<u16, u8>>,
    med: HashMap<u8, HashMap<u16, u16>>,
    high: HashMap<u8, HashMap<u16, u32>>,
    ultra: HashMap<u8, HashMap<u16, u64>>,
    divine: HashMap<u8, HashMap<u16, u128>>,
    port_combos: (Vec<u8>, Vec<u8>),
    port_range: u16,
    version: u32,
    synced_with_bridge: bool,
}

impl Drill {
    pub fn new_async(remote: Remote, port_range: u16) -> impl Future<Item=Drill, Error=HyxeError> {
        generate_total_drill_async(remote.clone(), port_range, false).and_then(move |(low, med, high, ultra, divine)| {
            Ok(Drill {
                low,
                med,
                high,
                ultra,
                divine,
                port_combos: generate_port_combos(port_range),
                port_range,
                version: 0,
                synced_with_bridge: true, //assumed! Version 0 should be synced with the server
            })
        }).from_err::<HyxeError>().map_err(|mut err| {
            err.printf()
        })
    }

    pub fn compute_next_version(&mut self, drill_update_object: DrillUpdateObject) -> (Drill, DrillUpdateObject) {
        let next_version = self.version + 1;
        let mut drill_next = Drill {
            low: xor2_u8(&self.low, &drill_update_object.low),
            med: xor2_u16(&self.med, &drill_update_object.med),
            high: xor2_u32(&self.high, &drill_update_object.high),
            ultra: xor2_u64(&self.ultra, &drill_update_object.ultra),
            divine: xor2_u128(&self.divine, &drill_update_object.divine),
            port_combos: drill_update_object.port_combos.clone(),
            port_range: self.port_range,
            version: self.version,
            synced_with_bridge: false, //nonzero version need to be synced across the bridge!
        };
        (drill_next, drill_update_object)
    }

    pub fn get_low(&self) -> &HashMap<u8, HashMap<u16, u8>> {
        &self.low
    }

    pub fn get_med(&self) -> &HashMap<u8, HashMap<u16, u16>> {
        &self.med
    }

    pub fn get_high(&self) -> &HashMap<u8, HashMap<u16, u32>> {
        &self.high
    }

    pub fn get_ultra(&self) -> &HashMap<u8, HashMap<u16, u64>> {
        &self.ultra
    }

    pub fn get_divine(&self) -> &HashMap<u8, HashMap<u16, u128>> {
        &self.divine
    }

    pub fn get_port_combos(&self) -> &(Vec<u8>, Vec<u8>) { &self.port_combos }

    pub fn get_version(&self) -> &u32 {
        &self.version
    }

    pub fn debug(&self) {
        println!("Low Security Constants:");
        for i in 0..=E_OF_X_START_INDEX {
            println!("[{}] ", i);
            for x in 0..self.port_range {
                print!("{} ", self.low.get(&i).unwrap().get(&x).unwrap());
            }
            println!();
        }

        println!("Medium Security Constants:");
        for i in 0..=E_OF_X_START_INDEX {
            println!("[{}] ", i);
            for x in 0..self.port_range {
                print!("{} ", self.med.get(&i).unwrap().get(&x).unwrap());
            }
            println!();
        }

        println!("High Security Constants:");
        for i in 0..=E_OF_X_START_INDEX {
            println!("[{}] ", i);
            for x in 0..self.port_range {
                print!("{} ", self.high.get(&i).unwrap().get(&x).unwrap());
            }
            println!();
        }

        println!("Ultra Security Constants:");
        for i in 0..=E_OF_X_START_INDEX {
            println!("[{}] ", i);
            for x in 0..self.port_range {
                print!("{} ", self.ultra.get(&i).unwrap().get(&x).unwrap());
            }
            println!();
        }

        println!("Divine Security Constants:");
        for i in 0..=E_OF_X_START_INDEX {
            println!("[{}] ", i);
            for x in 0..self.port_range {
                print!("{} ", self.divine.get(&i).unwrap().get(&x).unwrap());
            }
            println!();
        }
    }

    /// Returns the port range that this drill is built for
    pub fn get_port_range(&self) -> u16 {
        self.port_range
    }

    /// Returns a random value between 0 and port_range
    #[inline]
    pub fn get_random_port_index(&self) -> u8 {
        rand::thread_rng().gen_range(0, self.port_range)
    }

    /// When this drill is generated, it must be synced with the central server before it becomes usable. As such, this drill may be temporarily unsynced if the server has not validated it
    pub fn is_synced_with_bridge(&self) -> &bool {
        &self.synced_with_bridge
    }

    /// As the WaveformGenerator creates WIDs (wave identification numbers), it caps the iterative-index at port_range. In order to use this function,
    /// it must also keep an index, `full_idx`, going that keeps going above indefinitely. `full_idx` must RESET for each
    /// object!
    /// Math: To make it personalized, we want some k,j such that f(x) = k*sin(jx) where [ 0 < k < u8_max ] && [ 0 < j < u32_max ]
    pub fn calculate_wid(&self, full_idx: usize) -> f64 {
        let (k, j) = (*self.low.get(&E_OF_X_START_INDEX).unwrap().get(&0).unwrap(), *self.high.get(&E_OF_X_START_INDEX).unwrap().get(&0).unwrap());
        let inner: f64 = full_idx * j as f64;
        k * inner.sin()
    }

    ///Keep in mind: f(x) = k*sin(jx) where [ 0 < k < u8_max ] && [ 0 < j < u32_max ]
    pub fn calculate_wid_inverse(&self, wid: f64) -> usize {
        let (k, j) = (*self.low.get(&E_OF_X_START_INDEX).unwrap().get(&0).unwrap(), *self.high.get(&E_OF_X_START_INDEX).unwrap().get(&0).unwrap());
        let inner = wid / k as f64;
        inner.asin() / j as usize
    }

    pub fn calculate_pid(&self, full_idx: usize) -> f64 {
        let (k, j) = (*self.low.get(&E_OF_X_START_INDEX).unwrap().get(&1).unwrap(), *self.high.get(&E_OF_X_START_INDEX).unwrap().get(&1).unwrap());
        let inner: f64 = full_idx * j as f64;
        k * inner.sin()
    }

    ///Keep in mind: f(x) = k*sin(jx) where [ 0 < k < u8_max ] && [ 0 < j < u32_max ]
    pub fn calculate_pid_inverse(&self, wid: f64) -> usize {
        let (k, j) = (*self.low.get(&E_OF_X_START_INDEX).unwrap().get(&1).unwrap(), *self.high.get(&E_OF_X_START_INDEX).unwrap().get(&1).unwrap());
        let inner = wid / k as f64;
        inner.asin() / j as usize
    }
}

pub fn load(cid: &str) -> Option<Drill> {
    if let Ok(drill) = deserialize(cid) {
        return Some(drill);
    }
    None
}

pub fn generate_port_combos(port_range: u16) -> (Vec<u8>, Vec<u8>) {
    let (sources, dests) = (scramble_array(port_range, 10), scramble_array(port_range, 5));
    for port in 0..port_range {
        println!("[Drill] Mapping port {} to {}", sources[port], dests[port]);
    }

    (sources, dests)
}

pub const MAX_DRILL_VERIONS_IN_MEMORY: usize = 50;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Toolset {
    pub drill_map: HyxeObject<HashMap<usize, HyxeObject<Drill>>> //drill_version ~> Drill
}

impl Toolset {
    pub fn new_async(remote: Remote, port_range: u16, username: String) -> impl Future<Item=Toolset, Error=HyxeError> {
        //generate drill=f(0)
        Drill::new_async(remote, port_range).and_then(move |drill| {
            let mut map = HashMap::new();
            map.insert(0, HyxeObject::new(drill));
            let wrapper = HyxeObject::new(map);
            Ok(Toolset { drill_map: wrapper })
        }).from_err::<HyxeError>().map_err(|mut err| err.printf())
    }

    pub fn get_packet_coordinate_indices(&self, drill_version: &u32, pid: f64, wid: f64) -> Option<(usize, usize)> {
        if let Some(drill) = self.drill_map.get_object().get(drill_version as &usize) {}
        None
    }

    /**
        The client must call this function to propose the next drill version. The result of
        this function is: the function-caller gets the new drill as well as the DrillUpdateObject
        . The new drill should be placed into memory to await
    */
    pub fn propose_next_version(&mut self, dou: DrillUpdateObject) -> (HyxeObject<Drill>, DrillUpdateObject) {
        let current_version = self.drill_map.get_object().get(&(self.drill_map.get_object().len() - 1)).unwrap().get_object().version as usize;
        let next_version = current_version + 1;
        println!("Current version: {}", current_version);
        println!("Next version: {}", next_version);

        if self.drill_map.get_object().len() >= MAX_DRILL_VERIONS_IN_MEMORY {
            let pmutex = HyxeObject::clone(self.drill_map.get_object().get(&current_version).unwrap());
            let port_range = pmutex.get_object().port_range.clone();
            let next_version = (current_version.clone() + 1) as u32;
            //let mut dou = DrillUpdateObject::generate(port_range, next_version);
            let latest_drill = HyxeObject::clone(self.drill_map.get_object().get(&current_version).unwrap());
            //let owner = self.drill_map.get_object().pop_front().unwrap(); //transfer owner outside via popping
            let (new_drill, dou) = latest_drill.get_object().compute_next_version(dou);
            let new_version = new_drill.version;
            let new_drill = HyxeObject::new(new_drill);
            self.drill_map.get_object().insert(new_version as usize, new_drill.clone_ref());
            (new_drill, dou)
        } else {
            let port_range = self.drill_map.get_object().get(&current_version).unwrap().get_object().port_range.clone();
            let next_version = (current_version.clone() + 1) as u32;
            //let mut dou = DrillUpdateObject::generate(port_range, next_version);
            let new_drill = HyxeObject::clone(&self.drill_map).get_object().get(&current_version).unwrap().clone();

            let (new_drill, dou) = HyxeObject::clone(&self.drill_map).get_object().get(&current_version).unwrap().clone().get_object().compute_next_version(dou);
            let new_version = new_drill.version;
            let new_drill = HyxeObject::new(new_drill);
            self.drill_map.get_object().insert(new_version as usize, new_drill.clone_ref());
            (new_drill, dou)
        }
    }

    /**
        When this function is called, the drill version should already exist in the hashmap,
        but in the state of not being in-sync with the bridge. A drill cannot be used until
        it is synced with the bridge
    */
    pub fn implement_drill(&mut self, version: usize) -> Result<bool, HyxeError> {
        if let Some(drill) = self.get_drill(version) {
            if drill.get_object().synced_with_bridge {
                return Err(HyxeError::new("Drill already implemented!"));
            }

            (*drill.get_object()).synced_with_bridge = true;
            return Ok(true);
        }

        Err(HyxeError(format!("[Drill] Unable to find drill v{} needed to implement", version), false))
    }

    /**
        When the client sends an update packet to this node, we must deserialize the payload into a
        DrillUpdateObject. IF successful, we update the current drill and send back an
        UPDATE_DRILL_ACK to the original sender. THIS IS SERVERSIDE!
    */
    pub fn update_packet_received<F>(&mut self, remote: Remote, peer_nac: HyxeObject<NetworkAccount>, packet: ProcessedInboundPacket) -> Result<bool, HyxeError>
        where F: Fn(Option<ProcessedInboundPacket>, Remote) -> Result<String, HyxeError> + Send
    {
        if let Ok(new_dou) = bincode::deserialize::<DrillUpdateObject>(packet.get_data()) {
            let (mut next_drill, dou) = self.propose_next_version(new_dou);
            let next_vers = next_drill.get_object().version as usize;
            println!("[Drill] Updated drill version constructed {}", next_vers);
            //Now, this node will start accepting this drill version once implement_drill is called
            return self.implement_drill(next_vers).and_then(move |res| {
                let mut flag = Flags::DRILL_UPDATE_ACK_SUCCESS;
                if !res {
                    flag = Flags::DRILL_UPDATE_ACK_FAILURE;
                }

                //TODO: Ensure the destination IP used below is VALID! Create a hashmap of IP's perhaps? Or, demand a specific set of coordinates given by the drill?
                let (username, password) = unsafe { peer_nac.lock().get_credentials() };
                if let Some(mut packet) = generate_coms_packet(Vec::new(),
                                                               Arc::clone(&peer_nac),
                                                               &MAINFRAME_SERVER_IP.to_string(),
                                                               packet.get_src_ip(),
                                                               *packet.get_src_port(),
                                                               &username, &password,
                                                               next_drill.get_object().version - 1,
                                                               packet.get_eid(),
                                                               flag) {
                    // This function below executes via the remote... there is no need to run it here, just execute this function
                    peer_nac.lock().get_central_bridge().lock().send_packet_async(remote, packet, Some(move |packet: Option<ProcessedInboundPacket>, remote: Remote| {
                        Ok("".to_string())
                    }));
                }

                Ok(true)
            });
        }

        Err(HyxeError("[Drill] Unable to deserialize DOU!".to_string(), false))
    }

    /**
        When the other side of the bridge has synchronized the drill, it send this packet
        to allow the use of the new drill version. We simply flag the drill as "available"
        in this function. THIS IS CLIENT SIDE!
    */
    pub fn ack_update_packet_received(&mut self, packet: ProcessedInboundPacket) -> Result<bool, HyxeError> {
        println!("[Drill] ack_update_packet_received");
        let next_drill_version = (packet.get_drill_version() + 1) as usize;
        let mut drill_opt = self.drill_map.get_object();
        if let Some(drill) = drill_opt.get_mut(&next_drill_version) {
            drill.get_object().synced_with_bridge = true;
            println!("[Drill] version {} is now engaged", &drill.get_object().version);
            return Ok(true);
        }

        Err(HyxeError(format!("[Drill] ERROR: Unable to get drill version {}", next_drill_version), false))
    }

    pub fn get_drill(&self, version: usize) -> Option<HyxeObject<Drill>> {
        println!("[Drill] Getting drill version {}. Toolset has {} drill(s) ", &version, &self.drill_map.get_object().len());
        let obj = HyxeObject::clone(self.drill_map.get_object().get(&version).unwrap());
        println!("[Drill] Drill version {} obtained", version);
        Some(obj)
    }

    pub fn get_current_drill(&self) -> Option<HyxeObject<Drill>> {
        //let len = self.drill_map.get_object().len() - 1;
        //self.get_drill(len)
        //The last object in the array that is syned with the bridge is valid
        println!("av0");
        let max = self.drill_map.get_object().len();


        println!("av1 {}", max);
        let min = 0;
        for vers in (min..max).rev() {
            println!("[Drill] Checking drill version {}", vers);
            if let Some(drill) = self.drill_map.get_object().get(&vers) {
                println!("av2");
                if drill.get_object().synced_with_bridge {
                    println!("av3");
                    return Some(drill.clone_ref());
                }
            }
        }
        None
    }

    pub fn get_latest_drill_version(&self) -> Option<u32> {
        Some(*self.get_current_drill().unwrap().get_object().get_version())
    }

    pub fn get_rand<U: HyperRandom>(&self) -> Option<U> where U: HyperRandom {
        let num_drills = self.drill_map.get_object().len();
        println!("Getting drill for rand");
        let drill = self.get_current_drill().unwrap();
        println!("Got a drill for rand {}", U::get_marker());

        U::get_hyper_random(drill)
    }
}

pub trait HyperRandom {
    fn get_hyper_random(drill: HyxeObject<Drill>) -> Option<Self> where Self: Sized;
}

impl HyperRandom for u8 {
    #[inline]
    fn get_hyper_random(drill: HyxeObject<Drill>) -> Option<u8> {
        let v1 = *drill.get_object().get_low().get(&E_OF_X_START_INDEX).unwrap().get(&drill.get_random_port_index()).unwrap();
        let v2 = *drill.get_object().get_low().get(&E_OF_X_START_INDEX).unwrap().get(&drill.get_random_port_index()).unwrap();
        let v3 = rand::random::<u8>();
        Some(v1 ^ v2 ^ v3)
    }
}

impl HyperRandom for u16 {
    #[inline]
    fn get_hyper_random(drill: HyxeObject<Drill>) -> Option<u16> {
        let v1 = *drill.get_object().get_med().get(&E_OF_X_START_INDEX).unwrap().get(&drill.get_random_port_index()).unwrap();
        let v2 = *drill.get_object().get_med().get(&E_OF_X_START_INDEX).unwrap().get(&drill.get_random_port_index()).unwrap();
        let v3 = rand::random::<u16>();
        Some(v1 ^ v2 ^ v3)
    }
}

impl HyperRandom for u32 {
    #[inline]
    fn get_hyper_random(drill: HyxeObject<Drill>) -> Option<u32> {
        let v1 = *drill.get_object().get_high().get(&E_OF_X_START_INDEX).unwrap().get(&drill.get_random_port_index()).unwrap();
        let v2 = *drill.get_object().get_high().get(&E_OF_X_START_INDEX).unwrap().get(&drill.get_random_port_index()).unwrap();
        let v3 = rand::random::<u32>();
        Some(v1 ^ v2 ^ v3)
    }
}

impl HyperRandom for u64 {
    #[inline]
    fn get_hyper_random(drill: HyxeObject<Drill>) -> Option<u64> {
        let v1 = *drill.get_object().get_ultra().get(&E_OF_X_START_INDEX).unwrap().get(&drill.get_random_port_index()).unwrap();
        let v2 = *drill.get_object().get_ultra().get(&E_OF_X_START_INDEX).unwrap().get(&drill.get_random_port_index()).unwrap();
        let v3 = rand::random::<u64>();
        Some(v1 ^ v2 ^ v3)
    }
}

impl HyperRandom for u128 {
    #[inline]
    fn get_hyper_random(drill: HyxeObject<Drill>) -> Option<u128> {
        let v1 = *drill.get_object().get_divine().get(&E_OF_X_START_INDEX).unwrap().get(&drill.get_random_port_index()).unwrap();
        let v2 = *drill.get_object().get_divine().get(&E_OF_X_START_INDEX).unwrap().get(&drill.get_random_port_index()).unwrap();
        let v3 = rand::random::<u128>();
        Some(v1 ^ v2 ^ v3)
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DrillUpdateObject {
    pub low: HashMap<u8, HashMap<u16, u8>>,
    pub med: HashMap<u8, HashMap<u16, u16>>,
    pub high: HashMap<u8, HashMap<u16, u32>>,
    pub ultra: HashMap<u8, HashMap<u16, u64>>,
    pub divine: HashMap<u8, HashMap<u16, u128>>,
    pub port_combos: (Vec<u8>, Vec<u8>),
    pub version: u32,
}

impl DrillUpdateObject {
    /*pub fn generate(port_range: u16, version: u32) -> Self {
        DrillUpdateObject { low: generate_low(port_range), med: generate_med(port_range), high: generate_high(port_range), ultra: generate_ultra(port_range), divine: generate_divine(port_range), version }
    }*/
}

pub fn generate_total_drill_async(remote: Remote, port_range: u16, use_entropy_bank: bool) -> impl Future<Item=(HashMap<u8, HashMap<u16, u8>>, HashMap<u8, HashMap<u16, u16>>, HashMap<u8, HashMap<u16, u32>>, HashMap<u8, HashMap<u16, u64>>, HashMap<u8, HashMap<u16, u128>>), Error=HyxeError> {
    futures::lazy(move || {
        let (total_u8s, low_count, med_count, high_count, ultra_count, divine_count) = {
            let low_count = ((E_OF_X_START_INDEX + 1) * (port_range as usize)) as usize;
            let med_count = 2 * low_count;
            let high_count = 4 * low_count;
            let ultra_count = 8 * low_count;
            let divine_count = 16 * low_count;
            (low_count + med_count + high_count + ultra_count + divine_count, low_count, med_count, high_count, ultra_count, divine_count)
        };

        println!("[Drill] TODO: Fetching {} total bytes to construct drill...", total_u8s);
        QuantumRandom::random::next_u8s(remote, total_u8s).and_then(move |data| {
            if data.is_none() {
                return HyxeError::throw("[Drill] Unable to create drill due to empty set!");
            }

            let mut data = data.unwrap();
            println!("[Drill] Constructed Vec<u8> contains {} items. We wanted {}", data.len(), total_u8s);
            let (mut low, mut med, mut high, mut ultra, mut divine) = (HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
            let mut get_idx = 0;

            for z in 0..=E_OF_X_START_INDEX {
                low.insert(z, HashMap::new());
                med.insert(z, HashMap::new());
                high.insert(z, HashMap::new());
                ultra.insert(z, HashMap::new());
                divine.insert(z, HashMap::new());

                for x in 0..port_range {
                    let x = x as usize;
                    low.get_mut(&z).unwrap().insert(x, data[get_idx]);
                    get_idx += 1;

                    let arr = &[data[get_idx], data[get_idx + 1]];
                    med.get_mut(&z).unwrap().insert(x, LittleEndian::read_u16(arr));
                    get_idx += 2;

                    let arr = &data[get_idx..get_idx + 4];
                    high.get_mut(&z).unwrap().insert(x, LittleEndian::read_u32(arr));
                    get_idx += 4;

                    let arr = &data[get_idx..get_idx + 8];
                    ultra.get_mut(&z).unwrap().insert(x, LittleEndian::read_u64(arr));
                    get_idx += 8;

                    let arr = &data[get_idx..get_idx + 16];
                    divine.get_mut(&z).unwrap().insert(x, LittleEndian::read_u128(arr));
                    get_idx += 16;
                }
            }

            Ok((low, med, high, ultra, divine))
        })
    })
}

//current_version_map XOR ^ update_object = next_version_map
#[inline]
fn xor2_u8(map_old: &HashMap<u8, HashMap<u16, u8>>, update: &HashMap<u8, HashMap<u16, u8>>) -> HashMap<u8, HashMap<u16, u8>> {
    let mut ret: HashMap<u8, HashMap<u16, u8>> = HashMap::new();
    let port_range = map_old.get(&0).unwrap().len() as u16;
    for z in 0..=E_OF_X_START_INDEX {
        ret.insert(z, HashMap::new());
        for x in 0..port_range {
            let mut xored_value = map_old.get(&z).unwrap().get(&x).unwrap() ^ update.get(&z).unwrap().get(&x).unwrap();
            ret.get_mut(&z).unwrap().insert(x, xored_value);
        }
    }
    ret
}

#[inline]
fn xor2_u16(map_old: &HashMap<u8, HashMap<u16, u16>>, update: &HashMap<u8, HashMap<u16, u16>>) -> HashMap<u8, HashMap<u16, u16>> {
    let mut ret: HashMap<u8, HashMap<u16, u16>> = HashMap::new();
    let port_range = map_old.get(&0).unwrap().len() as u16;
    for z in 0..=E_OF_X_START_INDEX {
        ret.insert(z, HashMap::new());
        for x in 0..port_range {
            let mut xored_value = map_old.get(&z).unwrap().get(&x).unwrap() ^ update.get(&z).unwrap().get(&x).unwrap();
            ret.get_mut(&z).unwrap().insert(x, xored_value);
        }
    }
    ret
}

#[inline]
fn xor2_u32(map_old: &HashMap<u8, HashMap<u16, u32>>, update: &HashMap<u8, HashMap<u16, u32>>) -> HashMap<u8, HashMap<u16, u32>> {
    let mut ret: HashMap<u8, HashMap<u16, u32>> = HashMap::new();
    let port_range = map_old.get(&0).unwrap().len() as u16;
    for z in 0..=E_OF_X_START_INDEX {
        ret.insert(z, HashMap::new());
        for x in 0..port_range {
            let mut xored_value = map_old.get(&z).unwrap().get(&x).unwrap() ^ update.get(&z).unwrap().get(&x).unwrap();
            ret.get_mut(&z).unwrap().insert(x, xored_value);
        }
    }
    ret
}

#[inline]
fn xor2_u64(map_old: &HashMap<u8, HashMap<u16, u64>>, update: &HashMap<u8, HashMap<u16, u64>>) -> HashMap<u8, HashMap<u16, u64>> {
    let mut ret: HashMap<u8, HashMap<u16, u64>> = HashMap::new();
    let port_range = map_old.get(&0).unwrap().len() as u16;
    for z in 0..=E_OF_X_START_INDEX {
        ret.insert(z, HashMap::new());
        for x in 0..port_range {
            let mut xored_value = map_old.get(&z).unwrap().get(&x).unwrap() ^ update.get(&z).unwrap().get(&x).unwrap();
            ret.get_mut(&z).unwrap().insert(x, xored_value);
        }
    }
    ret
}

#[inline]
fn xor2_u128(map_old: &HashMap<u8, HashMap<u16, u128>>, update: &HashMap<u8, HashMap<u16, u128>>) -> HashMap<u8, HashMap<u16, u128>> {
    let mut ret: HashMap<u8, HashMap<u16, u128>> = HashMap::new();
    let port_range = map_old.get(&0).unwrap().len() as u16;
    for z in 0..=E_OF_X_START_INDEX {
        ret.insert(z, HashMap::new());
        for x in 0..port_range {
            let mut xored_value = map_old.get(&z).unwrap().get(&x).unwrap() ^ update.get(&z).unwrap().get(&x).unwrap();
            ret.get_mut(&z).unwrap().insert(x, xored_value);
        }
    }
    ret
}