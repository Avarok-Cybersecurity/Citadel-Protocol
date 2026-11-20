//! Sealing stored objects again under the account's key.
//!
//! Objects stored before account keys are sealed under a key their server also holds. Each is
//! sealed again the first time it is read; [`reseal`] reads a list of them now, for an
//! application that knows its paths. The server has no listing of an account's paths.

use crate::prelude::{ProtocolRemoteTargetExt, TargetLockedRemote};
use citadel_proto::prelude::{NetworkError, Ratchet};
use citadel_types::crypto::SecurityLevel;
use std::path::PathBuf;

/// A pulled object: where it was saved, and whether it was sealed again on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevfsPull {
    pub path: PathBuf,
    pub resealed: bool,
}

/// Reads each path, sealing again under the account's key every object stored before account
/// keys. Stops at the first failure. Each object is also saved locally, as by [`super::read`];
/// the caller owns those copies.
pub async fn reseal<P: Into<PathBuf> + Send, R: Ratchet>(
    remote: &impl TargetLockedRemote<R>,
    transfer_security_level: SecurityLevel,
    virtual_paths: impl IntoIterator<Item = P>,
) -> Result<Vec<RevfsPull>, NetworkError> {
    let mut pulled = Vec::new();
    for virtual_path in virtual_paths {
        pulled.push(
            remote
                .remote_encrypted_virtual_filesystem_pull_resealing(
                    virtual_path,
                    transfer_security_level,
                    false,
                )
                .await?,
        );
    }
    Ok(pulled)
}
