use hyxe_fs::prelude::*;
use hyxe_fs::system_file_manager::{load_file_types_by_ext, read};
use crate::network_account::NetworkAccount;
use crate::hypernode_account::CNAC_SERIALIZED_EXTENSION;
use crate::client_account::ClientNetworkAccountInner;
use crate::prelude::{ClientNetworkAccount, HyperNodeAccountInformation, NetworkAccountInner};
use crate::misc::AccountError;
use std::collections::HashMap;
use hyxe_fs::env::*;
use hyxe_crypt::hyper_ratchet::Ratchet;

/// This is called during the program init. This closure will install a new NAC if one does not
/// exist locally.
/// `cnacs_loaded` must also be present in order to validate that the local node's listed clients map to locally-existant CNACs. A "feed two birds with one scone" scenario
#[allow(unused_results)]
pub fn load_node_nac<R: Ratchet, Fcm: Ratchet>(directory_store: &DirectoryStore) -> Result<NetworkAccount<R, Fcm>, AccountError> {
    log::info!("[NAC-loader] Detecting local NAC...");
    // First, set the NAC_NODE_DEFAULT_STORE_LOCATION
    let file_location = directory_store.inner.read().nac_node_default_store_location.clone();

    let create_nac = |err: String| {
        if let Ok(nac) = NetworkAccount::<R, Fcm>::new(directory_store) {
            Ok(nac)
        } else {
            Err(AccountError::Generic(format!("[NAC-Loader] Unable to start application. Unable to create this node's NetworkAccount.\nError Message: {}", err.to_string())))
        }
    };

    match std::fs::File::open(&file_location) {
        Ok(_) => {
            log::info!("[NAC-Loader] Detected local NAC. Updating information...");
            match read::<NetworkAccountInner<R, Fcm>, _>(&file_location).map(NetworkAccount::<R, Fcm>::from){
                Ok(nac) => {
                    Ok(nac)
                }

                Err(err) =>{
                    create_nac(err.to_string())
                }
            }
        },

        Err(err) => {
            create_nac(err.to_string())
        }
    }
}

/// Loads all locally-stored CNACs, as well as the highest CID (used to update local nac incase improper shutdown)
#[allow(unused_results)]
pub fn load_cnac_files<R: Ratchet, Fcm: Ratchet>(directory_store: &DirectoryStore) -> Result<HashMap<u64, ClientNetworkAccount<R, Fcm>>, FsError<String>> {
    let read = directory_store.inner.read();
    let hyxe_nac_dir_impersonal = read.hyxe_nac_dir_impersonal.clone();
    let hyxe_nac_dir_personal = read.hyxe_nac_dir_personal.clone();
    std::mem::drop(read);

    let cnacs_impersonal = load_file_types_by_ext::<ClientNetworkAccountInner<R, Fcm>, _>(CNAC_SERIALIZED_EXTENSION, hyxe_nac_dir_impersonal)?;
    let cnacs_personal = load_file_types_by_ext::<ClientNetworkAccountInner<R, Fcm>, _>(CNAC_SERIALIZED_EXTENSION, hyxe_nac_dir_personal)?;
    log::info!("[CNAC Loader] Impersonal client network accounts loaded: {} | Personal client network accounts loaded: {}", cnacs_impersonal.len(), cnacs_personal.len());
    let mut ret = HashMap::with_capacity(cnacs_impersonal.len() + cnacs_personal.len());
    for cnac in cnacs_impersonal.into_iter().chain(cnacs_personal.into_iter()) {
        match ClientNetworkAccount::<R, Fcm>::load_safe(cnac.0, Some(cnac.1.clone()), None) {
            Ok(cnac) => {
                ret.insert(cnac.get_id(), cnac);
            },
            Err(err) => {
                log::error!("Error converting CNAC-inner into CNAC: {:?}. Deleting CNAC from local storage", err);
                // delete it. If this doesn't work, it could be because of OS error 13 (bad permissions)
                if let Err(err) = hyxe_fs::system_file_manager::delete_file_blocking(cnac.1) {
                    log::warn!("Unable to delete file: {}", err.to_string());
                }
            }
        }
    }

    ret.shrink_to_fit();

    Ok(ret)
}