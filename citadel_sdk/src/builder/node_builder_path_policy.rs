//! A server's path policy is required configuration: [`NodeBuilder::build`] refuses a server
//! node without one, and a peer node with one. There is no default policy.

use super::NodeBuilder;
use crate::prelude::{NodeType, PathPolicy, PlatformOps, Ratchet, ServerOnlySessionInitSettings};
use citadel_io::ErrorCode;

impl<R: Ratchet, T: PlatformOps> NodeBuilder<R, T> {
    /// The paths this server lets its peers use, their order, attempt timeouts and traffic
    /// classes (see [`PathPolicy`]). Required for [`NodeType::Server`]; refused on a peer. The
    /// server sends it to each client at connect and stamps each peer pair's effective plan into
    /// their key exchange.
    pub fn with_path_policy(&mut self, policy: PathPolicy) -> &mut Self {
        self.path_policy = Some(policy);
        self
    }
}

pub(super) fn check_path_policy(
    node_type: Option<&NodeType>,
    policy: Option<&PathPolicy>,
) -> Result<(), citadel_io::NetworkError> {
    let is_server = matches!(node_type, Some(NodeType::Server(_)));
    match (is_server, policy) {
        (true, None) => Err(citadel_io::error!(ErrorCode::NodePathPolicyMissing)),
        (false, Some(_)) => Err(citadel_io::error!(ErrorCode::NodePathPolicyNotServer)),
        _ => Ok(()),
    }
}

/// The server-only session settings with the policy folded in. A peer has neither.
pub(super) fn server_settings(
    settings: Option<ServerOnlySessionInitSettings>,
    policy: Option<PathPolicy>,
) -> Option<ServerOnlySessionInitSettings> {
    match policy {
        Some(policy) => {
            let mut settings = settings.unwrap_or_default();
            settings.path_policy = Some(policy);
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
    use crate::test_common::{localhost_path_policy, LOCALHOST_STUN_SERVERS};
    use citadel_io::ErrorCode;

    fn build_error(node_type: NodeType, with_policy: bool) -> Option<ErrorCode> {
        let mut builder = DefaultNodeBuilder::default();
        let _ = builder
            .with_node_type(node_type)
            .with_stun_servers(LOCALHOST_STUN_SERVERS);
        if with_policy {
            let _ = builder.with_path_policy(localhost_path_policy());
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
    fn a_server_without_a_path_policy_is_refused() {
        let server = NodeType::server("127.0.0.1:0").unwrap();
        assert_eq!(
            build_error(server, false),
            Some(ErrorCode::NodePathPolicyMissing)
        );
        assert_eq!(build_error(server, true), None);
    }

    #[test]
    fn a_peer_with_a_path_policy_is_refused() {
        assert_eq!(
            build_error(NodeType::Peer, true),
            Some(ErrorCode::NodePathPolicyNotServer)
        );
        assert_eq!(build_error(NodeType::Peer, false), None);
    }
}
