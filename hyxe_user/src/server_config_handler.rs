/*
use std::fmt::Write;

use std::sync::MutexGuard;

use hyxe_config::config_handler::{ConfigFile, FILE_END, FILE_HEADER, SECTION_END, SECTION_START, SUBSECTION_END, SUBSECTION_START};

use crate::misc::AccountError;
use crate::prelude::NetworkAccount;
use crate::client_account::ClientNetworkAccount;
use std::collections::HashMap;
//use log::info;

/// #
pub const CLIENTS_SECTION: &'static str = "clients";
/// #
pub const CIDS_SUBSECTION: &'static str = "cids";
/// #
pub const LAST_KNOWN_IPS: &'static str = "last_ips";
/// #
pub const USERNAMES: &'static str = "usernames";

/*
lazy_static! {
    /// The server configuration file. Only one per node. This path is typically in ~/.HyxeWave/config/server.hfg
    pub static ref SERVER_CONFIG_PATH: String = format!("{}server{}", HYXE_CONFIG_DIR.to_string(), CONFIG_EXT.to_string());
}
*/
#[allow(unused)]
fn get_default_server_config_string() -> String {
    let mut out = String::new();

    writeln!(out, "{}", FILE_HEADER).unwrap();
    writeln!(out, "{} {}", SECTION_START, CLIENTS_SECTION).unwrap();
    writeln!(out, "{} {} as map", SUBSECTION_START, CIDS_SUBSECTION).unwrap();
    writeln!(out, "{} {}", SUBSECTION_END, CIDS_SUBSECTION).unwrap();
    writeln!(out, "{} {} as map", SUBSECTION_START, LAST_KNOWN_IPS).unwrap();
    writeln!(out, "{} {}", SUBSECTION_END, LAST_KNOWN_IPS).unwrap();
    writeln!(out, "{} {}", SECTION_END, CLIENTS_SECTION).unwrap();
    writeln!(out, "{}", FILE_END).unwrap();

    out
}

/*
#[allow(unused_results)]
pub async fn check_config_validity(nac: &NetworkAccount, cnacs_loaded: &mut HashMap<u64, ClientNetworkAccount>) -> Result<(), AccountError<String>> {
    log::trace!(target: "lusna", "[ServerConfigHandler] Checking config validity");
    if let Some(item) = nac.read().await.config_file.as_ref() {
        let mut item = item.lock().await;
        if item.subsection_exists(CLIENTS_SECTION, CIDS_SUBSECTION) {
            if let Ok(cids_in_cfg) = item.get_subsection_mut(CLIENTS_SECTION, CIDS_SUBSECTION) {
                // Now, we need to see if there are any CNACs that don't yet exist in the config
                // This implies CNACs can be installed via drag-and-drop
                // TODO: Contemplate security of this feature
                let mut needs_recompile = false;
                'next_cnac: for (id, cnac) in cnacs_loaded.iter() {
                    log::trace!(target: "lusna", "checking loaded CNAC {} for correspondence in cfg", id);
                    let str_id = id.to_string();
                    for key in cids_in_cfg.fields.keys() {
                        if key == &str_id {
                            continue 'next_cnac;
                        }
                    }

                    // We have a loaded CNAC that doesn't correlate to any CID in the CFG. Add it to extend functionality
                    // of "drag n' drop" accounts
                    log::trace!(target: "lusna", "[ServerConfigHandler] Locally existent CNAC {} not present in config. Now adding ...", &str_id);
                    needs_recompile = true;
                    cids_in_cfg.add_map_item(str_id, cnac.read().await.username.as_str())
                        .map_err(|err| AccountError::IoError(err.to_string()))?;
                }

                let mut vals_to_remove = Vec::new();
                let borrow = &mut cids_in_cfg.fields;
                let ptr = borrow as *mut HashMap<String, FieldEntry>;
                // Now, check and see if there are any entries in the CFG that don't correlate with a CNAC (reverse)
                'next_entry: for (cid_in_cfg, _) in borrow.iter_mut() {
                    if let Ok(id) = u64::from_str(&cid_in_cfg) {
                        for (cid, _) in cnacs_loaded.iter() {
                            if id == *cid {
                                continue 'next_entry;
                            }
                        }

                        // We have a specific entry in the CFG that, despite scanning all the loaded CNACs,
                        // Does not exist in the loaded CNACs. The CNAC is missing. Delete the entry from the
                        // CFG
                        vals_to_remove.push(cid_in_cfg);
                    } else {
                        log::trace!(target: "lusna", "[ServerConfigHandler] Improperly formatted entry {}. Removing entry ...", cid_in_cfg);
                        vals_to_remove.push(cid_in_cfg);
                    }
                }


                if !vals_to_remove.is_empty() {
                    needs_recompile = true;
                    for cid in vals_to_remove {
                        unsafe { &mut *ptr }.remove(cid);
                    }
                }
                return if needs_recompile {
                    item.save().await.map_err(|err| AccountError::IoError(err.to_string()))
                } else {
                    Ok(())
                };
            }
        }
    }

    Err(AccountError::Generic("Invalid config. Either or both of the clients section and cid's subsection are absent".to_string()))
}
*/

/// Ensures that essential CNAC data is loaded into the NAC for runtime
#[allow(unused_results)]
pub fn sync_cnacs_and_nac(nac: &NetworkAccount, cnacs_loaded: &mut HashMap<u64, ClientNetworkAccount>) -> Result<(), AccountError<String>> {
    let mut write = nac.inner.write();
    let mut needs_save = false;

    write.cids_registered.retain(|cid, _e| {
        if !cnacs_loaded.contains_key(cid) {
            // if the NAC has a CID that doesn't map to a loaded CNAC, get rid of the entry in the NAC
            log::trace!(target: "lusna", "CID {} no longer exists on local storage. Removing entry from local NAC", cid);
            needs_save = true;
            false
        } else {
            true
        }
    });

    for (cid, cnac) in cnacs_loaded {
        // if a loaded CNAC doesn't map to a value in the NAC, add it to the NAC
        if !write.cids_registered.contains_key(cid) {
            log::trace!(target: "lusna", "CNAC {} was not synced to NAC. Syncing ...", cid);
            let username = cnac.get_username_blocking();
            write.cids_registered.insert(*cid, username);
            needs_save = true;
        }
    }

    std::mem::drop(write);

    if needs_save {
        nac.save_to_local_fs()
    } else {
        Ok(())
    }
}

/*
/// Asynchronously creates a server configuration file
pub async fn create_server_config_file() -> Result<ConfigFile, AccountError<String>> {
    ConfigFile::create(SERVER_CONFIG_PATH.replace(CONFIG_EXT, ""), Some(get_default_server_config_string()))
        .map_err(|err| AccountError::Generic(err.to_string())).await
}
*/

/// Adds an IP to the list under the given cid
pub async fn add_ip_to_config(cfg: &mut MutexGuard<'_, ConfigFile>, cid: u64, addr: String, save: bool) -> Result<(), AccountError<String>> {
    match cfg.add_map_field(CLIENTS_SECTION, LAST_KNOWN_IPS, cid, addr) {
        Ok(_) => {
            if save {
                cfg.save().await.map_err(|err| AccountError::IoError(err.to_string()))?;
            }

            Ok(())
        }

        Err(err) => {
            Err(AccountError::Generic(err.to_string()))
        }
    }
}*/

use crate::misc::AccountError;
use crate::network_account::NetworkAccount;
use std::collections::HashMap;
use crate::client_account::ClientNetworkAccount;
use hyxe_crypt::hyper_ratchet::Ratchet;
/// Ensures that essential CNAC data is loaded into the NAC for runtime. This only applies to CNACs that synchronize to the local FS (db is unnecessary)
#[allow(unused_results)]
pub fn sync_cnacs_and_nac_filesystem<R: Ratchet, Fcm: Ratchet>(nac: &NetworkAccount<R, Fcm>, cnacs_loaded: &mut HashMap<u64, ClientNetworkAccount<R, Fcm>>) -> Result<(), AccountError> {
    let mut write = nac.write();
    let cids_registered = &mut write.cids_registered;

    cids_registered.retain(|cid, _e| {
        if !cnacs_loaded.contains_key(cid) {
            // if the NAC has a CID that doesn't map to a loaded CNAC, get rid of the entry in the NAC
            log::trace!(target: "lusna", "CID {} no longer exists on local storage. Removing entry from local NAC", cid);
            false
        } else {
            true
        }
    });

    for (cid, cnac) in cnacs_loaded {
        // if a loaded CNAC doesn't map to a value in the NAC, add it to the NAC
        if !cids_registered.contains_key(cid) {
            log::trace!(target: "lusna", "CNAC {} was not synced to NAC. Syncing ...", cid);
            let username = cnac.get_username();
            cids_registered.insert(*cid, username);
        }
    }

    Ok(())
}