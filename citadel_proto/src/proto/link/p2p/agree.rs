//! WIRE-A (§12.4): both ends of a pair run the same link code. The Legacy campaign and the
//! manager speak the coordination topics differently (a Legacy retry exchanges Terms on
//! RETRY_RENDEZVOUS, a manager attempt only syncs; a Legacy campaign parks, a manager never
//! does), so a pair runs `Managed` only when both nodes are `Managed`; otherwise both run the
//! campaign. A peer below `LINK_MODE_SINCE` does not know the topic and is Legacy.

use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::wire::Topic;

use crate::constants::{protocol_version_at_least, LINK_MODE_SINCE};

/// The exchange of each end's link-manager mode, once per pair, before any path work.
pub(crate) const LINK_MODE: Topic = Topic::new(0x5032_0005);

/// Whether a pair whose ends are `Managed` (`true`) or `Legacy` (`false`) runs the manager. The
/// node's `LinkManagerMode` carries its clock and policy; on the wire only the variant matters.
pub(crate) fn both_managed(local_managed: bool, peer_managed: bool) -> bool {
    local_managed && peer_managed
}

/// Whether the pair runs `Managed`. Each end computes it from the same two values.
pub(crate) async fn agree_mode(
    app: &NetworkEndpoint,
    local_managed: bool,
    peer_version: Option<u32>,
) -> bool {
    if !protocol_version_at_least(peer_version, LINK_MODE_SINCE) {
        return false;
    }
    match app.on(LINK_MODE).sync_exchange_payload(local_managed).await {
        Ok(peer_managed) => both_managed(local_managed, peer_managed),
        Err(err) => {
            // Each end that fails here runs Legacy; the other end's exchange fails too (the
            // endpoint is one stream), so neither runs the manager alone.
            log::warn!(target: "citadel", "Link-mode exchange failed ({err}); running the campaign");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MANAGED: bool = true;
    const LEGACY: bool = false;

    #[test]
    fn a_pair_runs_the_manager_only_when_both_ends_do() {
        assert!(both_managed(MANAGED, MANAGED));
        assert!(!both_managed(MANAGED, LEGACY));
        assert!(!both_managed(LEGACY, MANAGED));
        assert!(!both_managed(LEGACY, LEGACY));
    }
}
