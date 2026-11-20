//! Where a node gets each account's identity key and its pins of peers' keys, which sign and
//! check every P2P key exchange (`citadel_proto::proto::peer::kex_auth`). A node given none
//! signs no exchange and reports every P2P channel as `PeerKexIdentity::Unsigned`.

use super::NodeBuilder;
use crate::prelude::{P2pKexIdentities, PlatformOps, Ratchet};

impl<R: Ratchet, T: PlatformOps> NodeBuilder<R, T> {
    /// The accounts' identity keys and pins. The node signs each of its stages of a P2P key
    /// exchange through it and checks the peer's stage against the key pinned for the peer; a
    /// stage signed by another key, or unsigned from a peer with a pin, builds no link.
    pub fn with_p2p_kex_identity(&mut self, identity: P2pKexIdentities) -> &mut Self {
        self.p2p_kex_identity = Some(identity);
        self
    }
}
