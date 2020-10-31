/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::any::Any;
#[macro_use]
use std::boxed::Box;
use std::fs::create_dir_all as mkdir;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::iter;
use std::path::Path;
use std::string::String;
use std::sync::Arc;

use bincode::ErrorKind;
use crossterm::{ClearType, Color, Crossterm};
use parking_lot::Mutex;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use tokio_core::reactor::Remote;

use crate::hyxewave::encrypt::Drill::Drill;
use crate::hyxewave::misc::Constants;
use crate::hyxewave::network::session::NetworkAccount::{load_nac, NetworkAccount};

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn get_home_dir() -> Mutex<String> {
    let p: Box<Path> = dirs_2::home_dir().unwrap().into_boxed_path();
    let j = p.to_str().unwrap();
    let v = format!("{}/.HyxeWave/", j);
    Mutex::new(v)
}

#[cfg(any(target_os = "windows"))]
fn get_home_dir() -> Mutex<String> {
    let p: Box<Path> = dirs_2::home_dir().unwrap().into_boxed_path();
    let j = p.to_str().unwrap();
    let v = format!("{}\\.HyxeWave\\", j);
    Mutex::new(v)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn format_path(input: String) -> Mutex<String> {
    Mutex::new(input.replace("\\", "/"))
}

#[cfg(any(target_os = "windows"))]
fn format_path(input: String) -> Mutex<String> {
    Mutex::new(input.replace("/", "\\"))
}

fn append_to_path(base: String, addition: &str) -> Mutex<String> {
    let mut val = base.clone();
    val.push_str(addition);
    format_path(val)
}

lazy_static! {
    pub static ref HYXE_HOME: Mutex<String> = get_home_dir();
    pub static ref HYXE_NAC_DIR: Mutex<String> = append_to_path(HYXE_HOME.lock().to_string(), "nac/");
    pub static ref HYXE_SERVER_DIR: Mutex<String> = append_to_path(HYXE_HOME.lock().to_string(), "server/");
    pub static ref HYXE_CONFIG_DIR: Mutex<String> = append_to_path(HYXE_HOME.lock().to_string(), "cfg/");
    pub static ref HYXE_VIRTUAL_DIR: Mutex<String> = append_to_path(HYXE_HOME.lock().to_string(), "virtual/");
    pub static ref CROSSTERM: Crossterm = Crossterm::new();
}

pub fn setup_directories() -> bool {
    let j = mkdir(Path::new(HYXE_HOME.lock().as_str())).is_ok();
    j &&
        mkdir(Path::new(HYXE_NAC_DIR.lock().as_str())).is_ok() &&
        mkdir(Path::new(HYXE_SERVER_DIR.lock().as_str())).is_ok() &&
        mkdir(Path::new(HYXE_CONFIG_DIR.lock().as_str())).is_ok() &&
        mkdir(Path::new(HYXE_VIRTUAL_DIR.lock().as_str())).is_ok()
}

pub fn printf(input: &str, fg: Color, bg: Color, newline: bool) {
    match newline {
        true => println!("{}", CROSSTERM.style(input).with(fg).on(bg)),
        false => print!("{}", CROSSTERM.style(input).with(fg).on(bg))
    }
}

pub fn printf_success(input: String) {
    println!("{}", CROSSTERM.style(input).with(Color::Green).on(Color::Black));
}

pub fn printf_err(input: &str) {
    println!("{}", CROSSTERM.style(input).with(Color::Red).on(Color::Black));
}

pub fn clear_terminal() {
    CROSSTERM.terminal().clear(ClearType::All);
}


pub fn serialize_drill_to_disk(cid: &str, drill: &Drill) {
    let mut fname = format!("{}{}", cid, ".drx");
    let mut path = format!("{}{}", HYXE_NAC_DIR.lock().to_string().clone().as_str(), fname);
    let mut writer = BufWriter::new(File::create(path).unwrap());
    bincode::serialize_into(writer, drill);
}


pub fn deserialize_drill_from_disk(cid: &str) -> Result<Drill, Box<ErrorKind>> {
    let mut fname = format!("{}{}", cid, ".drx");
    let mut path = format!("{}{}", HYXE_NAC_DIR.lock().to_string().clone().as_str(), fname);
    let mut reader = BufReader::new(File::open(path).unwrap());
    let mut drill: Result<Drill, Box<ErrorKind>> = bincode::config().deserialize_from(reader);
    drill
}

pub fn serialize_nac_to_disk(cid: &str, nac: &NetworkAccount) {
    let mut fname = format!("{}{}", cid, ".nac");
    let mut path = format!("{}{}", HYXE_NAC_DIR.lock().to_string().clone().as_str(), fname);
    let mut writer = BufWriter::new(File::create(path).unwrap());
    bincode::serialize_into(writer, nac);
}


pub fn deserialize_nac_from_disk(username: &str) -> Result<NetworkAccount, Box<ErrorKind>> {
    let mut fname = format!("{}{}", username, ".nac");
    let mut path = format!("{}{}", HYXE_NAC_DIR.lock().to_string().clone().as_str(), fname);
    let mut reader = BufReader::new(File::open(path).unwrap());
    let mut nac: Result<NetworkAccount, Box<ErrorKind>> = bincode::config().deserialize_from(reader);
    nac
}

pub fn serialize_hf_to_disk(cid: &str, nac: &NetworkAccount) {
    let mut fname = format!("{}{}", cid, ".nac");
    let mut path = format!("{}{}", HYXE_NAC_DIR.lock().to_string().clone().as_str(), fname);
    let mut writer = BufWriter::new(File::create(path).unwrap());
    bincode::serialize_into(writer, nac);
}


pub fn deserialize_hf_from_disk(cid: &str) -> NetworkAccount {
    let mut fname = format!("{}{}", cid, ".nac");
    let mut path = format!("{}{}", HYXE_NAC_DIR.lock().to_string().clone().as_str(), fname);
    let mut reader = BufReader::new(File::open(path).unwrap());
    let mut nac: NetworkAccount = bincode::config().deserialize_from(reader).unwrap();
    nac
}

pub fn serialize_entity_to_disk<T: serde::Serialize>(full_path: String, entity: T) {
    let mut writer = BufWriter::new(File::create(full_path).unwrap());
    bincode::serialize_into(writer, &entity);
}


pub fn deserialize_entity_from_disk<'de, T: serde::de::DeserializeOwned>(full_path: String) -> Result<T, Box<ErrorKind>> {
    let mut reader = BufReader::new(File::open(full_path).unwrap());
    let mut entity: Result<T, Box<ErrorKind>> = bincode::config().deserialize_from(reader);
    entity
}


pub fn port_is_wave_type(port: u16) -> bool {
    if port >= Constants::PORT_START && port < Constants::PORT_END {
        return true;
    }
    return false;
}

pub fn generate_rand_u64() -> u64 {
    rand::prelude::random::<u64>()
}

#[cfg(any(target_os = "windows"))]
pub fn load_nac_files(is_server: bool) {
    let base_dir = HYXE_NAC_DIR.lock().clone();
    let base_dir = base_dir.as_str();
    let paths = std::fs::read_dir(base_dir).unwrap();

    for path in paths {
        let file = path.unwrap().path();
        let file = file.to_str().unwrap();

        if !file.ends_with(".nac") {
            continue;
        }

        let pos_seperator = file.rfind("\\").unwrap();
        let (beginning, file_load) = file.split_at(pos_seperator);
        let file_load = file_load.replace(".nac", "").replace("\\", "");
        let file_load = file_load.as_str();
        println!("[NAC-LOADER] loading file {}, username = {}", file, file_load);

        load_nac(file_load, is_server);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn load_nac_files(is_server: bool) {
    let base_dir = HYXE_NAC_DIR.lock().clone();
    let base_dir = base_dir.as_str();
    let paths = std::fs::read_dir(base_dir).unwrap();

    for path in paths {
        let file = path.unwrap().path();
        let file = file.to_str().unwrap();

        if !file.ends_with(".nac") {
            continue;
        }

        let pos_seperator = file.rfind("/").unwrap() + 1;
        let (beginning, file_load) = file.split_at(pos_seperator);
        if file_load.ends_with(".nac") {
            let file_load = file_load.replace(".nac", "").replace("/", "");
            let file_load = file_load.as_str();
            println!("[NAC-LOADER] loading file {}, username = {}", file, file_load);
            load_nac(file_load, is_server);
        }
    }
}

pub fn generate_random_string(count: usize) -> String {
    let mut rng = thread_rng();
    iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(count)
        .collect()
}

pub fn is_even(value: usize) -> bool {
    value % 2 == 0
}

pub fn scramble_array(port_range: u16, strength: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = (0..port_range).collect();
    for i in 0..strength {
        thread_rng().shuffle(&mut vec);
    }
    vec
}

pub fn scramble_generic_array<T>(arr: &mut Vec<T>) {
    thread_rng().shuffle(arr);
}
