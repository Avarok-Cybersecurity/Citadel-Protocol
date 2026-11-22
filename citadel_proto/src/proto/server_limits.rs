//! What a server holds for connections that have not signed in yet, and for the work and queues
//! they can cause. Every limit is the operator's: a server node is built with [`ServerLimits`]
//! (`NodeBuilder::with_server_limits`) or not at all.

use crate::proto::outbound_total::OutboundTotal;
pub use crate::proto::peer::group_mail::GroupMailLimits;
use citadel_io::{error, ErrorCode, NetworkError};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A server's limits.
#[derive(Clone, Debug)]
pub struct ServerLimits {
    /// The most connections from one IP address the server holds before they have signed in or
    /// registered. Clients behind one NAT share an address, so it bounds their concurrent
    /// connects too.
    pub provisional_per_ip: NonZeroUsize,
    /// The most such connections the server holds in all.
    pub provisional_total: NonZeroUsize,
    /// Whether the server takes legacy registrations, whose password it hashes itself.
    pub legacy_registration: LegacyRegistration,
    /// The most bytes one peer-facing stream may hold queued for a client that is not reading.
    pub outbound_queued_per_stream: NonZeroUsize,
    /// The most bytes all peer-facing streams may hold queued together. A send that would pass
    /// it ends the stream holding the most.
    pub outbound_queued_total: NonZeroUsize,
}

/// Whether a server takes a legacy registration: one from a client below the post-quantum
/// sign-in, whose password the server hashes with Argon2id before it creates the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyRegistration {
    /// Refused: only post-quantum registrations, whose expensive work is the client's.
    Refused,
    /// Taken, with at most `concurrent_hashes` hashing at once; one beyond that is refused.
    Accepted { concurrent_hashes: NonZeroUsize },
}

/// Whether one more connection from `ip` may be held, given those held now (`held`: the source
/// address of each connection not yet signed in).
pub fn admit_provisional(
    limits: &ServerLimits,
    ip: IpAddr,
    held: impl Iterator<Item = IpAddr>,
) -> Result<(), NetworkError> {
    let (mut total, mut from_ip) = (0usize, 0usize);
    for held in held {
        total += 1;
        from_ip += usize::from(held == ip);
    }
    if total >= limits.provisional_total.get() {
        return Err(error!(
            ErrorCode::ProvisionalTotalAtCap,
            limits.provisional_total
        ));
    }
    if from_ip >= limits.provisional_per_ip.get() {
        return Err(error!(
            ErrorCode::ProvisionalPerIpAtCap,
            ip, limits.provisional_per_ip
        ));
    }
    Ok(())
}

/// A server's shared state for its limits: one per node, built from its [`ServerLimits`].
#[derive(Clone)]
pub(crate) struct ServerLoad {
    pub(crate) limits: ServerLimits,
    /// What the server holds for a group member that is away.
    pub(crate) group_mail: GroupMailLimits,
    legacy_hashes: Arc<AtomicUsize>,
    outbound_total: Arc<OutboundTotal>,
}

/// One legacy registration's turn to hash. The turn ends when this drops.
pub(crate) struct LegacyHashTurn(Arc<AtomicUsize>);

impl Drop for LegacyHashTurn {
    fn drop(&mut self) {
        let _ = self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ServerLoad {
    pub(crate) fn new(limits: ServerLimits, group_mail: GroupMailLimits) -> Self {
        let outbound_total = Arc::new(OutboundTotal::new(limits.outbound_queued_total.get()));
        Self {
            limits,
            group_mail,
            legacy_hashes: Arc::new(AtomicUsize::new(0)),
            outbound_total,
        }
    }

    /// A turn to hash a legacy registration's password, or why there is none.
    pub(crate) fn legacy_hash_turn(&self) -> Result<LegacyHashTurn, NetworkError> {
        let concurrent = match self.limits.legacy_registration {
            LegacyRegistration::Refused => {
                return Err(error!(ErrorCode::LegacyRegistrationRefused))
            }
            LegacyRegistration::Accepted { concurrent_hashes } => concurrent_hashes.get(),
        };
        let taken = self.legacy_hashes.fetch_add(1, Ordering::AcqRel);
        let turn = LegacyHashTurn(self.legacy_hashes.clone());
        if taken >= concurrent {
            return Err(error!(ErrorCode::LegacyRegistrationBusy, concurrent));
        }
        Ok(turn)
    }

    /// The total every peer-facing stream of this server also counts against.
    pub(crate) fn outbound_total(&self) -> Arc<OutboundTotal> {
        self.outbound_total.clone()
    }
}

#[cfg(test)]
#[path = "server_limits_tests.rs"]
mod tests;
