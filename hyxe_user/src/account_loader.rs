use hyxe_fs::prelude::*;
use hyxe_fs::system_file_manager::{load_file_types_by_ext, read};
use crate::network_account::{NetworkAccount, NAC_NODE_DEFAULT_STORE_LOCATION};
use crate::hypernode_account::{CNAC_SERIALIZED_EXTENSION, NAC_SERIALIZED_EXTENSION};
use crate::client_account::ClientNetworkAccountInner;
use crate::prelude::{ClientNetworkAccount, HyperNodeAccountInformation, NetworkAccountInner};
use crate::misc::AccountError;
use std::collections::HashMap;
use hyxe_fs::env::{HYXE_NAC_DIR_IMPERSONAL, HYXE_NAC_DIR_PERSONAL, HYXE_SERVER_DIR};
use crate::server_config_handler::sync_cnacs_and_nac;

/// This is called during the program init. This closure will install a new NAC if one does not
/// exist locally.
/// `cnacs_loaded` must also be present in order to validate that the local node's listed clients map to locally-existant CNACs. A "feed two birds with one scone" scenario
#[allow(unused_results)]
pub fn load_node_nac(cnacs_loaded: &mut HashMap<u64, ClientNetworkAccount>) -> Result<NetworkAccount, AccountError<String>> {
    log::info!("[NAC-loader] Detecting local NAC...");
    // First, set the NAC_NODE_DEFAULT_STORE_LOCATION
    let file_location = (HYXE_SERVER_DIR.lock().unwrap().as_ref().unwrap().clone() + "default_server." + NAC_SERIALIZED_EXTENSION).to_string();
    NAC_NODE_DEFAULT_STORE_LOCATION.lock().unwrap().replace(file_location.clone());

    match std::fs::File::open(&file_location) {
        Ok(_) => {
            log::info!("[NAC-Loader] Detected local NAC. Updating information...");
            match read::<NetworkAccountInner, _>(&file_location) {
                Ok(inner) => {
                    let nac = NetworkAccount::new_from_local_fs(inner);
                    sync_cnacs_and_nac(&nac, cnacs_loaded)?;
                    Ok(nac)
                },
                Err(err) => Err(AccountError::Generic(err.to_string()))
            }
        },
        Err(err) => {
            if let Ok(nac) = NetworkAccount::new_local() {
                nac.save_to_local_fs()?;
                Ok(nac)
            } else {
                Err(AccountError::Generic(format!("[NAC-Loader] Unable to start application. Unable to create this node's NetworkAccount.\nError Message: {}", err.to_string())))
            }
        }
    }
}

/// Loads all locally-stored CNACs, as well as the highest CID (used to update local nac incase improper shutdown)
#[allow(unused_results)]
pub async fn load_cnac_files() -> Result<HashMap<u64, ClientNetworkAccount>, FsError<String>> {
    let cnacs_impersonal = load_file_types_by_ext::<ClientNetworkAccountInner, _>(CNAC_SERIALIZED_EXTENSION, HYXE_NAC_DIR_IMPERSONAL.lock().unwrap().as_ref().unwrap()).await?;
    let cnacs_personal = load_file_types_by_ext::<ClientNetworkAccountInner, _>(CNAC_SERIALIZED_EXTENSION, HYXE_NAC_DIR_PERSONAL.lock().unwrap().as_ref().unwrap()).await?;
    log::info!("[CNAC Loader] Impersonal client network accounts loaded: {} | Personal client network accounts loaded: {}", cnacs_impersonal.len(), cnacs_personal.len());
    let mut ret = HashMap::with_capacity(cnacs_impersonal.len() + cnacs_personal.len());
    for cnac in cnacs_impersonal.into_iter().chain(cnacs_personal.into_iter()) {
        match ClientNetworkAccount::load_safe_from_fs(cnac.0, cnac.1.clone()).await {
            Ok(cnac) => {
                ret.insert(cnac.get_id(), cnac);
            },
            Err(err) => {
                log::error!("Error converting CNAC-inner into CNAC: {}. Deleting CNAC from local storage", err.to_string());
                // delete it. If this doesn't work, it could be because of OS error 13 (bad permissions)
                if let Err(err) = hyxe_fs::system_file_manager::delete_file(cnac.1).await {
                    log::warn!("Unable to delete file: {}", err.to_string());
                }
            }
        }
    }

    ret.shrink_to_fit();

    Ok(ret)
}

/// Creates and internally-loads a CNAC, ready for use. This does not load safely, as it is expected the data is serialized
/// via the normal method
pub async fn load_cnac_from_bytes_test<T: AsRef<[u8]>>(serialized_bytes: T, test_nac: &NetworkAccount) -> Result<ClientNetworkAccount, AccountError<String>> {
    let serialized_bytes = serialized_bytes.as_ref();

    let mut inner = hyxe_fs::system_file_manager::bytes_to_type::<ClientNetworkAccountInner>(serialized_bytes).map_err(|err| AccountError::Generic(err.to_string()))?;
    inner.adjacent_nac = Some(test_nac.clone());

    Ok(ClientNetworkAccount::from(inner))
    //ClientNetworkAccount::load_safe_from_fs(inner, ClientNetworkAccount::generate_local_save_path(cid, is_personal)).await
}

