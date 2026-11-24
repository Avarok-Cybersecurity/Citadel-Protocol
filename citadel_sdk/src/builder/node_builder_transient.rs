//! Whether a server allows transient accounts.
//!
//! A transient account is a session with its own CID that the server never persists and that has
//! no password: the client proposes a fresh identifier, the server gives it a CID for the life of
//! the connection, and nothing about it outlives the session. A client asks for one with
//! `AuthenticationRequest::transient` or `ServerConnectionSettingsBuilder::transient`.
//!
//! The option is a server setting: [`NodeBuilder::build`] refuses it on a peer
//! ([`ErrorCode::NodeTransientAccountsNotServer`]). It sets the one field the protocol reads,
//! [`ServerMiscSettings::allow_transient_connections`], so there is a single source of truth.

use super::NodeBuilder;
use crate::prelude::{NodeType, PlatformOps, Ratchet, ServerMiscSettings};
use citadel_io::{ErrorCode, NetworkError};

impl<R: Ratchet, T: PlatformOps> NodeBuilder<R, T> {
    /// Whether this server gives a client a transient account: a session with its own CID that
    /// the server never persists and that has no password.
    ///
    /// **Without this call transient accounts are allowed.** That default is a deliberate product
    /// decision approved by the project owner (2026-11-24), not an implicit fallback: a transient
    /// account still has an identity (its CID) for as long as it is connected, and allowing it
    /// keeps every existing server and client working as before.
    ///
    /// Passing `false` makes every account on this server a registered one. The server gives up
    /// connections from clients that hold no account here (for example one that wants a single
    /// short exchange before deciding to register), and gains the guarantee that every session
    /// belongs to an account it stores. A refused client receives
    /// [`ErrorCode::PasswordlessUnsupported`], distinct from every other failure; registered
    /// accounts are unaffected.
    ///
    /// Refused on a peer ([`ErrorCode::NodeTransientAccountsNotServer`]). With
    /// [`Self::with_server_misc_settings`] as well: `false` here wins whatever the settings hold
    /// (their field cannot say whether it was chosen or defaulted), and `true` here with settings
    /// that say `false` is a contradiction `build` refuses
    /// ([`ErrorCode::NodeTransientAccountsConflict`]).
    pub fn with_transient_accounts(&mut self, allowed: bool) -> &mut Self {
        self.transient_accounts = Some(allowed);
        self
    }
}

pub(super) fn check_transient_accounts(
    node_type: Option<&NodeType>,
    transient_accounts: Option<bool>,
) -> Result<(), NetworkError> {
    let is_server = matches!(node_type, Some(NodeType::Server(_)));
    match (is_server, transient_accounts) {
        (false, Some(_)) => Err(citadel_io::error!(
            ErrorCode::NodeTransientAccountsNotServer
        )),
        _ => Ok(()),
    }
}

/// The server misc settings with the option folded into their one transient field.
pub(super) fn with_transient_accounts(
    misc: Option<ServerMiscSettings>,
    transient_accounts: Option<bool>,
) -> Result<Option<ServerMiscSettings>, NetworkError> {
    match (transient_accounts, misc) {
        (None, misc) => Ok(misc),
        (Some(true), Some(misc)) if !misc.allow_transient_connections => {
            Err(citadel_io::error!(ErrorCode::NodeTransientAccountsConflict))
        }
        (Some(allowed), misc) => Ok(Some(ServerMiscSettings {
            allow_transient_connections: allowed,
            ..misc.unwrap_or_default()
        })),
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::with_transient_accounts;
    use crate::builder::node_builder::DefaultNodeBuilder;
    use crate::prefabs::server::empty::EmptyKernel;
    use crate::prelude::{NodeType, ServerMiscSettings};
    use crate::test_common::LOCALHOST_STUN_SERVERS;
    use citadel_io::ErrorCode;

    fn misc(allowed: bool) -> Option<ServerMiscSettings> {
        Some(ServerMiscSettings {
            allow_transient_connections: allowed,
            ..Default::default()
        })
    }

    fn resolved(misc: Option<ServerMiscSettings>, option: Option<bool>) -> Option<bool> {
        with_transient_accounts(misc, option)
            .expect("no contradiction")
            .map(|misc| misc.allow_transient_connections)
    }

    #[test]
    fn the_option_sets_the_one_field_the_protocol_reads() {
        assert_eq!(resolved(None, Some(false)), Some(false));
        assert_eq!(resolved(None, Some(true)), Some(true));
    }

    #[test]
    fn without_the_option_the_settings_are_untouched() {
        assert_eq!(resolved(None, None), None);
        assert_eq!(resolved(misc(false), None), Some(false));
        assert_eq!(resolved(misc(true), None), Some(true));
    }

    #[test]
    fn disallowing_wins_over_the_settings() {
        assert_eq!(resolved(misc(true), Some(false)), Some(false));
        assert_eq!(resolved(misc(false), Some(false)), Some(false));
        assert_eq!(resolved(misc(true), Some(true)), Some(true));
    }

    #[test]
    fn allowing_against_settings_that_disallow_is_refused() {
        let Err(err) = with_transient_accounts(misc(false), Some(true)) else {
            panic!("a contradiction was resolved silently");
        };
        assert_eq!(err.code(), ErrorCode::NodeTransientAccountsConflict);
    }

    #[test]
    fn the_rest_of_the_settings_survive_the_option() {
        let custom = ServerMiscSettings {
            allow_transient_connections: true,
            credential_requirements: citadel_user::credentials::CredentialRequirements {
                min_password_length: 13,
                ..Default::default()
            },
            ..Default::default()
        };
        let folded = with_transient_accounts(Some(custom), Some(false))
            .unwrap()
            .unwrap();
        assert_eq!(folded.credential_requirements.min_password_length, 13);
    }

    fn build_error(node_type: NodeType, option: Option<bool>) -> Option<ErrorCode> {
        let mut builder = DefaultNodeBuilder::default();
        let _ = builder
            .with_node_type(node_type)
            .with_link_manager(crate::prelude::LinkManagerMode::Legacy)
            .with_max_security_level(crate::test_common::localhost_max_security_level())
            .with_stun_servers(LOCALHOST_STUN_SERVERS);
        if node_type.is_server() {
            let _ = builder
                .with_path_policy(crate::test_common::localhost_path_policy())
                .with_server_limits(crate::test_common::localhost_server_limits());
        }
        if let Some(allowed) = option {
            let _ = builder.with_transient_accounts(allowed);
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
    fn a_peer_given_the_option_is_refused() {
        for allowed in [true, false] {
            assert_eq!(
                build_error(NodeType::Peer, Some(allowed)),
                Some(ErrorCode::NodeTransientAccountsNotServer)
            );
        }
        assert_eq!(build_error(NodeType::Peer, None), None);
    }

    #[test]
    fn a_server_takes_the_option_either_way() {
        let server = NodeType::server("127.0.0.1:0").unwrap();
        for option in [Some(true), Some(false), None] {
            assert_eq!(build_error(server, option), None);
        }
    }

    #[test]
    fn a_contradiction_fails_the_build() {
        let mut builder = DefaultNodeBuilder::default();
        let _ = builder
            .with_node_type(NodeType::server("127.0.0.1:0").unwrap())
            .with_link_manager(crate::prelude::LinkManagerMode::Legacy)
            .with_max_security_level(crate::test_common::localhost_max_security_level())
            .with_stun_servers(LOCALHOST_STUN_SERVERS)
            .with_path_policy(crate::test_common::localhost_path_policy())
            .with_server_limits(crate::test_common::localhost_server_limits())
            .with_server_misc_settings(misc(false).unwrap())
            .with_transient_accounts(true);
        let Err(err) = builder.build(EmptyKernel::default()) else {
            panic!("a contradiction was built");
        };
        let code = err
            .downcast_ref::<citadel_io::NetworkError>()
            .expect("a typed error")
            .code();
        assert_eq!(code, ErrorCode::NodeTransientAccountsConflict);
    }
}
