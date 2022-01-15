/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */


use serde_derive::{Deserialize, Serialize};

use crate::{HyxeObject, SecurityLevel};
use crate::hyxewave::encrypt::Drill::Drill;
use crate::hyxewave::encrypt::HyCryptAF::decrypt_bytes;
use crate::hyxewave::encrypt::HyCryptAF::LinearHycryptor;
use crate::hyxewave::misc::Utility::*;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct HyxeFile {
    cid: Option<u64>,
    drill_version: Option<u32>,
    virtual_file_name: Option<String>,
    data_encrypted_bytes: Option<Vec<u8>>,

    #[serde(skip)]
    real_file_path: Option<String>, //we want to update this value onload

    real_file_name: Option<String>,
}

impl HyxeFile {
    pub fn new() -> Self {
        HyxeFile { cid: None, drill_version: None, virtual_file_name: None, data_encrypted_bytes: None, real_file_path: None, real_file_name: Some(generate_random_string(222)) }
    }

    pub fn replace_data(&mut self, file_name_virtual: String, cid: u64, data: &Vec<u8>, encryptor: &LinearHycryptor, drill: HyxeObject<Drill>) {
        self.cid = Some(cid);
        self.drill_version = Some(*drill.get_object().get_version());
        self.data_encrypted_bytes = Some(encryptor.encrypt_bytes(data, drill, &SecurityLevel::DIVINE, &0).into_bytes());
        self.virtual_file_name = Some(file_name_virtual);
    }

    pub fn save_to_disk(&mut self) -> bool {
        self.update_file_path();
        if let Some(data) = &self.data_encrypted_bytes {
            let full_path = format!("{}{}", self.real_file_path.clone().unwrap(), self.real_file_name.clone().unwrap());
            println!("[HyxeFile] SAVING {} to {}", self.virtual_file_name.clone().unwrap(), full_path);

            serialize_entity_to_disk(full_path, data.to_owned());
            self.data_encrypted_bytes = None; //free memory
            return true;
        }
        false
    }

    pub fn load_from_disk(&mut self, drill: HyxeObject<Drill>) -> Option<Vec<u8>> {
        self.update_file_path();
        if let Some(file_name) = &self.real_file_name {
            let full_path = format!("{}{}", self.real_file_path.clone().unwrap(), file_name);
            println!("[HyxeFile] LOADING {} from {}", self.virtual_file_name.clone().unwrap(), full_path);

            if let Ok(encrypted_data) = deserialize_entity_from_disk(full_path) {
                return Some(decrypt_bytes(&encrypted_data, drill, &SecurityLevel::DIVINE, &0));
            }
        }
        None
    }

    /**
        This function should be called on init of a server/client to recalculate the path in the case data is moved to another location.
        The filename remains the same, but the path changes (possibly)
    */
    fn update_file_path(&mut self) {
        self.real_file_path = Some(HYXE_NAC_DIR.lock().clone())
    }

    pub fn get_drill_version(&self) -> u32 {
        self.drill_version.unwrap()
    }
}