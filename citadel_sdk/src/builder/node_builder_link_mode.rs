//! A node's link mode is required configuration: [`NodeBuilder::build`] refuses a node built
//! without one. There is no default mode (PCND): `Legacy` keeps today's behaviour, `Managed` turns
//! on the RobustConnectionManager's, and the caller says which.

use super::NodeBuilder;
use crate::prelude::{LinkManagerMode, PlatformOps, Ratchet};
use citadel_io::ErrorCode;

impl<R: Ratchet, T: PlatformOps> NodeBuilder<R, T> {
    /// How this node keeps its links: [`LinkManagerMode::Legacy`], or
    /// [`LinkManagerMode::Managed`] with the clock its deadlines read and the `LinkPolicy` its
    /// links are kept under (the reattach grace among them). Required.
    pub fn with_link_manager(&mut self, mode: LinkManagerMode) -> &mut Self {
        self.link_mode = Some(mode);
        self
    }
}

pub(super) fn required_link_mode(
    mode: Option<LinkManagerMode>,
) -> Result<LinkManagerMode, citadel_io::NetworkError> {
    mode.ok_or_else(|| citadel_io::error!(ErrorCode::NodeLinkManagerMissing))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_without_a_link_mode_is_refused() {
        let err = required_link_mode(None).unwrap_err();
        assert!(err.to_string().contains("link mode"), "{err}");
        assert!(matches!(
            required_link_mode(Some(LinkManagerMode::Legacy)),
            Ok(LinkManagerMode::Legacy)
        ));
    }
}
