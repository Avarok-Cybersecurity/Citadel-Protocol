//! The bounds on the address candidates a peer sends for a hole punch.
//!
//! Every address in the expanded candidate pool receives a barrage of SYN packets, so the
//! peer's lists and its NAT model decide how many hosts this node sends to and which. An honest
//! peer's candidates are a handful of addresses; one that exceeds the bounds below, or names an
//! address no unicast punch can use, ends the attempt before any packet is sent.

use crate::error::FirewallError;
use crate::nat_identification::MAX_OCTET_DELTA;
use crate::udp_traversal::hole_punch_config::AddrBand;
use std::net::{IpAddr, SocketAddr};

/// The internal addresses a peer may list. The driver lists one per hole-punch socket, and binds
/// a primary socket plus at most one of the other family, so an honest peer sends one or two.
/// Four leaves room for a version that binds more.
pub(crate) const MAX_PEER_INTERNAL_ADDRS: usize = 4;

/// The observed (server-reflexive) addresses a peer may list: one per hole-punch socket, the
/// same as [`MAX_PEER_INTERNAL_ADDRS`].
pub(crate) const MAX_PEER_REFLEXIVE_ADDRS: usize = MAX_PEER_INTERNAL_ADDRS;

/// The widest offset range a delta model yields (`average..=3 * average` at the largest
/// average [`MAX_OCTET_DELTA`]).
const MAX_DELTA_SPAN: usize = 2 * MAX_OCTET_DELTA as usize + 1;

/// The bands one prediction makes: one per IP offset, then the external IPv6, the internal IP
/// and the peer's own address.
const MAX_BANDS_PER_PREDICTION: usize = MAX_DELTA_SPAN + 3;

/// The addresses one internal address expands to: each predicted band times its ports, plus the
/// two loopback bands every internal address adds.
const MAX_ADDRS_PER_INTERNAL: usize = MAX_BANDS_PER_PREDICTION * MAX_DELTA_SPAN + 2;

/// The most addresses an honest peer's candidates expand to. Derived from the bounds above, so
/// it never refuses an honest peer; it fails an attempt only if the expansion outgrows them.
pub(crate) const MAX_CANDIDATE_ADDRS: usize =
    MAX_PEER_INTERNAL_ADDRS * MAX_ADDRS_PER_INTERNAL + MAX_PEER_REFLEXIVE_ADDRS;

/// Fails when either of the peer's lists is longer than its bound.
pub(crate) fn check_peer_candidates(
    internal: &[SocketAddr],
    reflexive: &[SocketAddr],
) -> Result<(), FirewallError> {
    for (kind, list, max) in [
        ("internal", internal, MAX_PEER_INTERNAL_ADDRS),
        ("reflexive", reflexive, MAX_PEER_REFLEXIVE_ADDRS),
    ] {
        if list.len() > max {
            return Err(FirewallError::firewall_hole_punch(format!(
                "the peer listed {} {kind} addresses; at most {max} are accepted",
                list.len()
            )));
        }
    }
    Ok(())
}

/// Fails when the expanded pool holds more than [`MAX_CANDIDATE_ADDRS`] addresses, or an
/// address a unicast punch cannot use (multicast, or the IPv4 broadcast address).
pub(crate) fn check_candidate_pool(pool: &[AddrBand]) -> Result<(), FirewallError> {
    if let Some(band) = pool.iter().find(|band| !is_unicast(&band.necessary_ip)) {
        return Err(FirewallError::firewall_hole_punch(format!(
            "the peer's candidates include {}, which is not a unicast address",
            band.necessary_ip
        )));
    }
    let total: usize = pool.iter().map(|band| band.anticipated_ports.len()).sum();
    if total > MAX_CANDIDATE_ADDRS {
        return Err(FirewallError::firewall_hole_punch(format!(
            "the peer's candidates expand to {total} addresses; at most {MAX_CANDIDATE_ADDRS} are accepted"
        )));
    }
    Ok(())
}

fn is_unicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => !ip.is_multicast(),
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "candidate_bounds_tests.rs"]
mod tests;
