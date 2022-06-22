use hyxe_fs::prelude::*;
use hyxe_fs::system_file_manager::load_file_types_by_ext;
use crate::hypernode_account::CNAC_SERIALIZED_EXTENSION;
use crate::client_account::ClientNetworkAccountInner;
use crate::prelude::ClientNetworkAccount;
use std::collections::HashMap;
use hyxe_fs::env::*;
use hyxe_crypt::hyper_ratchet::Ratchet;

/// Loads all locally-stored CNACs, as well as the highest CID (used to update local nac incase improper shutdown)
#[allow(unused_results)]
pub fn load_cnac_files<R: Ratchet, Fcm: Ratchet>(ds: &DirectoryStore) -> Result<HashMap<u64, ClientNetworkAccount<R, Fcm>>, FsError<String>> {
    let hyxe_nac_dir_impersonal = ds.hyxe_nac_dir_impersonal.as_str();
    let hyxe_nac_dir_personal = ds.hyxe_nac_dir_personal.as_str();

    let cnacs_impersonal = load_file_types_by_ext::<ClientNetworkAccountInner<R, Fcm>, _>(CNAC_SERIALIZED_EXTENSION, hyxe_nac_dir_impersonal)?;
    let cnacs_personal = load_file_types_by_ext::<ClientNetworkAccountInner<R, Fcm>, _>(CNAC_SERIALIZED_EXTENSION, hyxe_nac_dir_personal)?;
    log::trace!(target: "lusna", "[CNAC Loader] Impersonal client network accounts loaded: {} | Personal client network accounts loaded: {}", cnacs_impersonal.len(), cnacs_personal.len());

    let mut ret = HashMap::with_capacity(cnacs_impersonal.len() + cnacs_personal.len());
    for cnac in cnacs_impersonal.into_iter().chain(cnacs_personal.into_iter()) {
        match ClientNetworkAccount::<R, Fcm>::load_safe(cnac.0) {
            Ok(cnac) => {
                ret.insert(cnac.get_cid(), cnac);
            },
            Err(err) => {
                log::error!(target: "lusna", "Error converting CNAC-inner into CNAC: {:?}. Deleting CNAC from local storage", err);
                // delete it. If this doesn't work, it could be because of OS error 13 (bad permissions)
                if let Err(err) = hyxe_fs::system_file_manager::delete_file_blocking(cnac.1) {
                    log::warn!(target: "lusna", "Unable to delete file: {}", err.to_string());
                }
            }
        }
    }

    ret.shrink_to_fit();

    Ok(ret)
}