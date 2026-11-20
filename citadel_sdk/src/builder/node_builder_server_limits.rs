//! A server's limits are required configuration: [`NodeBuilder::build`] refuses a server node
//! without them, and a peer node with them. There are no default limits.

use super::NodeBuilder;
use crate::prelude::{NodeType, PlatformOps, Ratchet, ServerLimits, ServerOnlySessionInitSettings};
use citadel_io::ErrorCode;

impl<R: Ratchet, T: PlatformOps> NodeBuilder<R, T> {
    /// How much this server holds for connections that have not signed in, how it takes legacy
    /// registrations, and how much its streams may queue (see [`ServerLimits`]). Required for
    /// [`NodeType::Server`]; refused on a peer.
    pub fn with_server_limits(&mut self, limits: ServerLimits) -> &mut Self {
        self.server_limits = Some(limits);
        self
    }
}

pub(super) fn check_server_limits(
    node_type: Option<&NodeType>,
    limits: Option<&ServerLimits>,
) -> Result<(), citadel_io::NetworkError> {
    let is_server = matches!(node_type, Some(NodeType::Server(_)));
    match (is_server, limits) {
        (true, None) => Err(citadel_io::error!(ErrorCode::NodeServerLimitsMissing)),
        (false, Some(_)) => Err(citadel_io::error!(ErrorCode::NodeServerLimitsNotServer)),
        _ => Ok(()),
    }
}

/// The server-only session settings with the limits folded in. A peer has neither.
pub(super) fn with_limits(
    settings: Option<ServerOnlySessionInitSettings>,
    limits: Option<ServerLimits>,
) -> Option<ServerOnlySessionInitSettings> {
    match limits {
        Some(limits) => {
            let mut settings = settings.unwrap_or_default();
            settings.limits = Some(limits);
            Some(settings)
        }
        None => settings,
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use crate::builder::node_builder::DefaultNodeBuilder;
    use crate::prefabs::server::empty::EmptyKernel;
    use crate::prelude::NodeType;
    use crate::test_common::{
        localhost_path_policy, localhost_server_limits, LOCALHOST_STUN_SERVERS,
    };
    use citadel_io::ErrorCode;

    fn build_error(node_type: NodeType, with_limits: bool) -> Option<ErrorCode> {
        let mut builder = DefaultNodeBuilder::default();
        let _ = builder
            .with_node_type(node_type)
            .with_link_manager(crate::prelude::LinkManagerMode::Legacy)
            .with_max_security_level(crate::test_common::localhost_max_security_level())
            .with_stun_servers(LOCALHOST_STUN_SERVERS);
        if node_type.is_server() {
            let _ = builder.with_path_policy(localhost_path_policy());
        }
        if with_limits {
            let _ = builder.with_server_limits(localhost_server_limits());
        }
        match builder.build(EmptyKernel::default()) {
            Ok(_) => None,
            Err(err) => Some(
                err.downcast_ref::<citadel_io::NetworkError>()
                    .expect("a typed error")
                    .code(),
            ),
        }
    }

    #[test]
    fn a_server_without_limits_is_refused() {
        let server = NodeType::server("127.0.0.1:0").unwrap();
        assert_eq!(
            build_error(server, false),
            Some(ErrorCode::NodeServerLimitsMissing)
        );
        assert_eq!(build_error(server, true), None);
    }

    #[test]
    fn a_peer_with_limits_is_refused() {
        assert_eq!(
            build_error(NodeType::Peer, true),
            Some(ErrorCode::NodeServerLimitsNotServer)
        );
        assert_eq!(build_error(NodeType::Peer, false), None);
    }
}
