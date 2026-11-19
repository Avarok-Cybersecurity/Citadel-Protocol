//! Which end of a peer pair acts first: one rule (S-P4), the lower CID (owner decision D2,
//! `citadel_negotiation::Role::for_pair`). Each tiebreak of the dial, the key exchange, the
//! route and the relay reads it here; a pair whose ends share a CID has no order, so neither
//! end leads and neither follows.

use citadel_negotiation::Role;

/// Whether `local` leads toward `peer` (the lower CID).
pub(crate) fn leads(local: u64, peer: u64) -> bool {
    Role::for_pair(local, peer) == Some(Role::Leader)
}

/// Whether `local` follows `peer` (the higher CID).
pub(crate) fn follows(local: u64, peer: u64) -> bool {
    Role::for_pair(local, peer) == Some(Role::Loser)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lower_cid_leads_and_equal_cids_have_no_order() {
        assert!(leads(1, 2) && follows(2, 1));
        assert!(!leads(2, 1) && !follows(1, 2));
        assert!(!leads(3, 3) && !follows(3, 3));
    }
}
