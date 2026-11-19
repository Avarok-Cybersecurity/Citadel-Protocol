//! Which wave layout a group uses, decided from protocol versions.
//!
//! The sender asks of its peer's version; the receiver asks of the version in the group's
//! header, which the group's AEAD covers end to end. Two nodes at or above
//! [`WAVE_BINDING_SINCE`] therefore always use `Bound` with each other.

use crate::constants::{protocol_version_at_least, WAVE_BINDING_SINCE};
use citadel_crypt::scramble::wave_binding::WaveBinding;

/// The layout of waves exchanged with a node of `protocol_version` (`None`: unknown, so the
/// pre-binding layout, which is all such a node can read).
pub(crate) fn wave_binding_for(protocol_version: Option<u32>) -> WaveBinding {
    if protocol_version_at_least(protocol_version, WAVE_BINDING_SINCE) {
        WaveBinding::Bound
    } else {
        WaveBinding::Unbound
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_semver::prelude::*;

    fn version(patch: usize) -> Option<u32> {
        Some(Semver::new(0, 12, patch).to_u32().unwrap())
    }

    #[test]
    fn nodes_at_or_above_the_gate_bind_their_waves() {
        assert_eq!(wave_binding_for(version(4)), WaveBinding::Bound);
        assert_eq!(
            wave_binding_for(Some(*crate::constants::PROTOCOL_VERSION)),
            WaveBinding::Bound
        );
    }

    #[test]
    fn older_or_unknown_nodes_get_the_unbound_layout() {
        assert_eq!(wave_binding_for(version(3)), WaveBinding::Unbound);
        assert_eq!(wave_binding_for(None), WaveBinding::Unbound);
    }
}
