//! WIRE-A (§12.4): both ends of a pair run the same link code. The Legacy campaign and the
//! manager speak the coordination topics differently (a Legacy retry exchanges Terms on
//! RETRY_RENDEZVOUS, a manager attempt only syncs; a Legacy campaign parks, a manager never
//! does), so a pair runs `Managed` only when both nodes are `Managed`; otherwise both run the
//! campaign. A peer below `LINK_MODE_SINCE` does not know the topic and is Legacy.

use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::wire::Topic;

use crate::constants::{protocol_version_at_least, LINK_MODE_SINCE};
use crate::proto::link::mode::LinkManagerMode;

/// The exchange of each end's link-manager mode, once per pair, before any path work.
pub(crate) const LINK_MODE: Topic = Topic::new(0x5032_0005);

/// Whether a pair whose ends run `local` and `peer` runs the manager.
pub(crate) fn both_managed(local: LinkManagerMode, peer: LinkManagerMode) -> bool {
    local == LinkManagerMode::Managed && peer == LinkManagerMode::Managed
}

/// The mode the pair runs. Each end computes it from the same two values.
pub(crate) async fn agree_mode(
    app: &NetworkEndpoint,
    local: LinkManagerMode,
    peer_version: Option<u32>,
) -> LinkManagerMode {
    if !protocol_version_at_least(peer_version, LINK_MODE_SINCE) {
        return LinkManagerMode::Legacy;
    }
    let managed = local == LinkManagerMode::Managed;
    match app.on(LINK_MODE).sync_exchange_payload(managed).await {
        Ok(peer_managed) => {
            let peer = if peer_managed {
                LinkManagerMode::Managed
            } else {
                LinkManagerMode::Legacy
            };
            if both_managed(local, peer) {
                LinkManagerMode::Managed
            } else {
                LinkManagerMode::Legacy
            }
        }
        Err(err) => {
            // Each end that fails here runs Legacy; the other end's exchange fails too (the
            // endpoint is one stream), so neither runs the manager alone.
            log::warn!(target: "citadel", "Link-mode exchange failed ({err}); running the campaign");
            LinkManagerMode::Legacy
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use LinkManagerMode::{Legacy, Managed};

    #[test]
    fn a_pair_runs_the_manager_only_when_both_ends_do() {
        assert!(both_managed(Managed, Managed));
        assert!(!both_managed(Managed, Legacy));
        assert!(!both_managed(Legacy, Managed));
        assert!(!both_managed(Legacy, Legacy));
    }
}
