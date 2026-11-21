//! Which adjacent nodes this node takes part with, decided from their protocol version.
//!
//! A node takes part only with a node in its own `major.minor` release at
//! [`OLDEST_PEER_PROTOCOL_VERSION`] or later. Anything else is refused by name
//! ([`ErrorCode::ProtocolVersionUnsupported`]) before any work is done for it: there are no
//! translations for an older node. Each `*_SINCE` gate in [`crate::constants`] at or below the
//! oldest admitted version therefore always holds for a node that got this far.

use crate::constants::{MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION};
use citadel_io::{error, ErrorCode, NetworkError};
use embedded_semver::prelude::*;

/// The oldest protocol version a node takes part with. Raised with every release while there are
/// no deployments that must keep working across one; lowering it below the current version means
/// every `*_SINCE` gate above it must handle the older node.
pub const OLDEST_PEER_PROTOCOL_VERSION: (u8, u8, u8) =
    (MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);

/// `Ok` when this node takes part with a node announcing `version`; otherwise the named refusal.
pub fn check_peer_protocol_version(version: u32) -> Result<(), NetworkError> {
    let theirs =
        Semver::from_u32(version).map_err(|_| error!(ErrorCode::PreconnectSemverParseFailed))?;
    let theirs = (theirs.major, theirs.minor, theirs.patch);
    let oldest = (
        OLDEST_PEER_PROTOCOL_VERSION.0 as usize,
        OLDEST_PEER_PROTOCOL_VERSION.1 as usize,
        OLDEST_PEER_PROTOCOL_VERSION.2 as usize,
    );
    let same_release = theirs.0 == oldest.0 && theirs.1 == oldest.1;
    if same_release && theirs >= oldest {
        return Ok(());
    }
    Err(error!(
        ErrorCode::ProtocolVersionUnsupported,
        format!("{}.{}.{}", theirs.0, theirs.1, theirs.2),
        format!("{}.{}.{}", oldest.0, oldest.1, oldest.2)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(major: usize, minor: usize, patch: usize) -> u32 {
        Semver::new(major, minor, patch).to_u32().unwrap()
    }

    fn oldest() -> (usize, usize, usize) {
        (
            OLDEST_PEER_PROTOCOL_VERSION.0 as usize,
            OLDEST_PEER_PROTOCOL_VERSION.1 as usize,
            OLDEST_PEER_PROTOCOL_VERSION.2 as usize,
        )
    }

    fn refused(version: u32) -> bool {
        matches!(
            check_peer_protocol_version(version).map_err(|err| err.code()),
            Err(ErrorCode::ProtocolVersionUnsupported)
        )
    }

    #[test]
    fn this_node_and_a_later_patch_are_admitted() {
        let (major, minor, patch) = oldest();
        check_peer_protocol_version(*crate::constants::PROTOCOL_VERSION).unwrap();
        check_peer_protocol_version(version(major, minor, patch)).unwrap();
        check_peer_protocol_version(version(major, minor, patch + 1)).unwrap();
    }

    #[test]
    fn an_older_patch_is_refused_by_name() {
        let (major, minor, patch) = oldest();
        assert!(
            patch > 0,
            "the oldest admitted patch must leave an older one to refuse"
        );
        assert!(refused(version(major, minor, patch - 1)));
        assert!(refused(version(major, minor, 0)));
        let message = check_peer_protocol_version(version(major, minor, patch - 1))
            .unwrap_err()
            .into_string();
        assert!(
            message.contains(&format!("{major}.{minor}.{}", patch - 1)),
            "{message}"
        );
    }

    #[test]
    fn another_release_is_refused_whichever_way_it_differs() {
        let (major, minor, patch) = oldest();
        assert!(refused(version(major, minor + 1, 0)));
        assert!(refused(version(major, minor - 1, patch)));
        assert!(refused(version(major + 1, minor, patch)));
    }

    #[test]
    fn an_unreadable_version_is_refused_as_unreadable() {
        let err = check_peer_protocol_version(u32::MAX).unwrap_err();
        assert_eq!(err.code(), ErrorCode::PreconnectSemverParseFailed);
    }
}
