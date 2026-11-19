//! A node's maximum security level is required configuration: [`NodeBuilder::build`] refuses a
//! node without one. There is no default maximum.

use super::NodeBuilder;
use crate::prelude::{PlatformOps, Ratchet};
use citadel_io::ErrorCode;
use citadel_types::crypto::MaxSecurityLevel;

impl<R: Ratchet, T: PlatformOps> NodeBuilder<R, T> {
    /// The most security layers this node builds a link with. Every level a peer, the server or
    /// an unauthenticated registration names is checked against it before anything is built,
    /// and one above it is refused. Required for every node.
    pub fn with_max_security_level(&mut self, level: MaxSecurityLevel) -> &mut Self {
        self.max_security_level = Some(level);
        self
    }
}

pub(super) fn required_max_security_level(
    level: Option<MaxSecurityLevel>,
) -> Result<MaxSecurityLevel, citadel_io::NetworkError> {
    level.ok_or_else(|| citadel_io::error!(ErrorCode::NodeMaxSecurityLevelMissing))
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use crate::builder::node_builder::DefaultNodeBuilder;
    use crate::prefabs::server::empty::EmptyKernel;
    use crate::prelude::NodeType;
    use crate::test_common::LOCALHOST_STUN_SERVERS;
    use citadel_io::ErrorCode;
    use citadel_types::crypto::{MaxSecurityLevel, SecurityLevel};

    #[test]
    fn a_node_without_a_maximum_security_level_is_refused() {
        let mut builder = DefaultNodeBuilder::default();
        let _ = builder
            .with_node_type(NodeType::Peer)
            .with_stun_servers(LOCALHOST_STUN_SERVERS);
        let Err(err) = builder.build(EmptyKernel::default()) else {
            panic!("a node without a maximum security level must be refused");
        };
        assert_eq!(
            err.downcast_ref::<citadel_io::NetworkError>()
                .expect("a typed error")
                .code(),
            ErrorCode::NodeMaxSecurityLevelMissing
        );
        let max = MaxSecurityLevel::new(SecurityLevel::Extreme).unwrap();
        assert!(builder
            .with_max_security_level(max)
            .build(EmptyKernel::default())
            .is_ok());
    }
}
