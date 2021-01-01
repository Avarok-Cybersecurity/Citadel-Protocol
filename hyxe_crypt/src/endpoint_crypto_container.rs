#![allow(missing_docs)]

use crate::toolset::Toolset;
use crate::hyper_ratchet::HyperRatchet;

/// a container that holds both the PQC and toolset for an endpoint connection
pub struct PeerSessionCrypto {
    pub toolset: Toolset,
    latest_hyper_ratchet_version_committed: u32
}

impl PeerSessionCrypto {
    /// Creates a new [PeerSessionCrypto] instance
    pub fn new(toolset: Toolset) -> Self {
        let latest_hyper_ratchet_version_committed = toolset.get_most_recent_hyper_ratchet_version();
        Self { toolset, latest_hyper_ratchet_version_committed }
    }

    /// Gets a specific drill version, or, gets the latest version comitted
    pub fn get_hyper_ratchet(&self, version: Option<u32>) -> Option<&HyperRatchet> {
        self.toolset.get_hyper_ratchet(version.unwrap_or(self.latest_hyper_ratchet_version_committed))
    }

    /// This should only be called when Bob receives the new DOU during the ReKey phase, or, when Alice receives confirmation
    /// that the endpoint updated the drill
    pub fn commit_next_hyper_ratchet_version(&mut self, newest_version: HyperRatchet) -> Option<()> {
        self.toolset.update_from(newest_version)?;
        let cur_vers = self.latest_hyper_ratchet_version_committed;
        let next_vers = cur_vers.wrapping_add(1);
        self.latest_hyper_ratchet_version_committed = next_vers;

        Some(())
    }
}