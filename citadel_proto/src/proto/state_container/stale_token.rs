//! Whether a disconnect signal names a connection other than the live one (S-C3: the check was
//! written out three times, at the two local P2P disconnect commands and at the signal from the
//! server).

use super::includes::*;

impl<R: Ratchet> StateContainerInner<R> {
    /// `token` names a connection with `target` that is not the one live now: a signal about a
    /// connection already replaced, to be dropped. A signal naming no connection, or about a peer
    /// with no live connection, is not stale.
    pub(crate) fn is_stale_disconnect(&self, target: u64, token: Option<&DisconnectToken>) -> bool {
        match (token, self.active_virtual_connections.get(&target)) {
            (Some(token), Some(live)) => live.p2p_connection_id != token.connection_id,
            _ => false,
        }
    }
}
