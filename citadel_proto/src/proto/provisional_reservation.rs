//! A client's claim on a provisional key, held from the moment its connect is admitted until its
//! session is registered under that key.
//!
//! The admission check and the registration are separated by the transport connect, so without a
//! claim two connects for one account both pass the check, and the second's registration replaces
//! the first's session mid-handshake. The claim is given back on drop, so a connect that fails
//! before registering never blocks the next one.

use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::session_manager::{CitadelSessionManager, ProvisionalKey};
use citadel_crypt::ratchets::Ratchet;

pub(crate) struct ProvisionalReservation<R: Ratchet, T: PlatformOps> {
    manager: CitadelSessionManager<R, T>,
    key: ProvisionalKey,
}

impl<R: Ratchet, T: PlatformOps> ProvisionalReservation<R, T> {
    /// Called with the manager's state already borrowed as `claims`, so the check and the claim
    /// are one step. `None` if the key is already claimed.
    pub(crate) fn claim(
        claims: &mut std::collections::HashSet<ProvisionalKey>,
        manager: &CitadelSessionManager<R, T>,
        key: &ProvisionalKey,
    ) -> Option<Self> {
        claims.insert(key.clone()).then(|| Self {
            manager: manager.clone(),
            key: key.clone(),
        })
    }
}

impl<R: Ratchet, T: PlatformOps> Drop for ProvisionalReservation<R, T> {
    fn drop(&mut self) {
        let _ = inner_mut!(self.manager)
            .provisional_reservations
            .remove(&self.key);
    }
}
