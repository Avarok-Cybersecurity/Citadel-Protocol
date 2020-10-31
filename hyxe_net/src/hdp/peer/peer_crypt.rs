use nanoserde::{DeBin, SerBin};
use ez_pqcrypto::PostQuantumContainer;
use hyxe_crypt::toolset::Toolset;
use hyxe_crypt::drill::Drill;
use hyxe_crypt::drill_update::DrillUpdateObject;
use crate::error::NetworkError;
use std::sync::Arc;

pub const KEP_STAGE0: u8 = 0;
pub const KEP_STAGE1: u8 = 1;
pub const KEP_INIT_REKEY: u8 = 2;
pub const KEP_ACCEPT_REKEY: u8 = 3;


#[derive(Clone, DeBin, SerBin, Debug)]
pub enum KeyExchangeProcess {
    // alice sends public key
    Stage0(Vec<u8>),
    // Bob sends ciphertext, and encrypted nonce
    Stage1(Vec<u8>, Vec<u8>),
    // Alice sends encrypted toolset over
    Stage2(Vec<u8>),
    // Bob sends ACK
    Stage3,
    // Re-key. Should be done periodically, handled by the channel layer
    // contains the DOU
    PerformReKey(Vec<u8>),
    // returns the drill version that the not just updated to
    ReKeyReturnStatus(u32)
}

pub struct PeerSessionCrypto {
    pub pqc: Arc<PostQuantumContainer>,
    pub toolset: Toolset,
    latest_drill_version_commited: u32
}

impl PeerSessionCrypto {
    pub fn new(pqc: PostQuantumContainer, toolset: Toolset) -> Self {
        let pqc = Arc::new(pqc);
        let latest_drill_version_commited = toolset.get_most_recent_drill_version();
        Self { pqc, toolset, latest_drill_version_commited }
    }

    /// Gets a specific drill version, or, gets the latest version comitted
    pub fn get_drill(&self, version: Option<u32>) -> Option<&Drill> {
        self.toolset.get_drill(version.unwrap_or(self.latest_drill_version_commited))
    }

    /// Updates the toolset and gets the DUO. Does not change the latest committed version. Comitting
    /// must be done manually AFTER receiving confirmation that the other side was updated
    pub fn generate(&mut self) -> Result<DrillUpdateObject, NetworkError> {
        self.toolset.update().map_err(|err| NetworkError::Generic(err.to_string()))
    }

    /// This should only be called when Bob receives the new DOU during the ReKey phase, or, when Alice receives confirmation
    /// that the endpoint updated the drill
    pub fn commit_next_drill_version(&mut self) {
        let cur_vers = self.latest_drill_version_commited;
        let next_vers = cur_vers.wrapping_add(1);
        self.latest_drill_version_commited = next_vers;
    }
}