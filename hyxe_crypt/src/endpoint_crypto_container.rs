#![allow(missing_docs)]

use ez_pqcrypto::PostQuantumContainer;
use crate::toolset::Toolset;
use crate::drill::Drill;
use crate::drill_update::DrillUpdateObject;
use std::sync::Arc;
use crate::misc::CryptError;

/// a container that holds both the PQC and toolset for an endpoint connection
pub struct PeerSessionCrypto {
    pub pqc: Arc<PostQuantumContainer>,
    pub toolset: Toolset,
    latest_drill_version_commited: u32
}

impl PeerSessionCrypto {
    /// Creates a new [PeerSessionCrypto] instance
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
    pub fn generate(&mut self) -> Result<DrillUpdateObject, CryptError<String>> {
        self.toolset.update()
    }

    /// This should only be called when Bob receives the new DOU during the ReKey phase, or, when Alice receives confirmation
    /// that the endpoint updated the drill
    pub fn commit_next_drill_version(&mut self) {
        let cur_vers = self.latest_drill_version_commited;
        let next_vers = cur_vers.wrapping_add(1);
        self.latest_drill_version_commited = next_vers;
    }

    /// Clones both the PQC and desired drill version
    pub fn get_pqc_and_drill(&self, drill_version: Option<u32>) -> Option<(Arc<PostQuantumContainer>, Drill)> {
        self.get_drill(drill_version)
            .map(|drill| (self.pqc.clone(), drill.clone()))
    }

    /// Borrows both the PQC and desired drill version
    pub fn borrow_pqc_and_drill(&self, drill_version: Option<u32>) -> Option<(&Arc<PostQuantumContainer>, &Drill)> {
        self.get_drill(drill_version)
            .and_then(|drill| Some((&self.pqc, drill)))
    }
}