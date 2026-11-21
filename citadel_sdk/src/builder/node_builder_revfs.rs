//! Where a node gets each account's RE-VFS key. There is no default key: a node given no source
//! refuses every RE-VFS push ([`citadel_io::ErrorCode::RevfsKeyMissing`]) and reads only objects
//! stored before account keys existed.

use super::NodeBuilder;
use crate::prelude::{PlatformOps, Ratchet, RevfsKeySource};
use std::sync::Arc;

impl<R: Ratchet, T: PlatformOps> NodeBuilder<R, T> {
    /// The source of each account's RE-VFS key ([`crate::prelude::RevfsKey::derive`], from the
    /// account's recovery or identity seed). Objects are sealed under it before they leave the
    /// device, so the server or peer storing them cannot read them. The node never stores or
    /// generates a seed.
    pub fn with_revfs_key_source(&mut self, source: impl RevfsKeySource + 'static) -> &mut Self {
        self.revfs_keys = Some(Arc::new(source));
        self
    }
}
