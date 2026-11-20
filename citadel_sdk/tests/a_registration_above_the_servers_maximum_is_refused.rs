#![cfg(not(target_family = "wasm"))]
//! A registration is the one exchange a server runs for someone who has not authenticated, and
//! every layer of its security level is a key exchange the server performs. A server therefore
//! refuses a registration above its maximum security level before building anything: the client
//! hears why, and the same account registers at a level the server admits.

#[cfg(all(test, feature = "localhost-testing"))]
#[path = "common/group.rs"]
#[allow(dead_code)]
mod group;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::group::GroupTestKernel;
    use citadel_io::tokio;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{
        localhost_max_security_level, managed, server_test_node, ManualClock,
    };
    use std::time::Duration;

    const PASSWORD: &str = "password";

    fn settings(level: SecurityLevel) -> SessionSecuritySettings {
        SessionSecuritySettingsBuilder::default()
            .with_security_level(level)
            .build()
            .expect("valid settings")
    }

    async fn register(
        remote: &NodeRemote<StackedRatchet>,
        addr: std::net::SocketAddr,
        username: &str,
        level: SecurityLevel,
    ) -> Result<RegisterSuccess, NetworkError> {
        remote
            .register(
                addr,
                username,
                username,
                PASSWORD,
                settings(level),
                None,
                CertVerification::SelfSignedAccepted,
            )
            .await
    }

    async fn client(
        remote: NodeRemote<StackedRatchet>,
        addr: std::net::SocketAddr,
        username: String,
    ) -> Result<(), NetworkError> {
        let Err(refused) = register(&remote, addr, &username, SecurityLevel::High).await else {
            panic!("a registration above the server's maximum is refused");
        };
        assert!(
            refused.to_string().contains("above this node's maximum"),
            "refused as: {refused}"
        );
        register(&remote, addr, &username, SecurityLevel::Reinforced).await?;
        let conn = remote
            .connect_with_defaults(
                AuthenticationRequest::credentialed(username.clone(), PASSWORD),
                CertVerification::SelfSignedAccepted,
            )
            .await?;
        conn.shutdown_kernel().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_registration_above_the_servers_maximum_is_refused() {
        citadel_logging::setup_log();
        // Both ends on clocks nobody moves: no deadline can end a registration or the login,
        // however slow the host (#391).
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |b| {
            let _ = b
                .with_max_security_level(MaxSecurityLevel::new(SecurityLevel::Reinforced).unwrap())
                .with_link_manager(managed(ManualClock::new()));
        });
        let username = format!("r_{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let node = DefaultNodeBuilder::default()
            .with_link_manager(managed(ManualClock::new()))
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(localhost_max_security_level())
            .build(GroupTestKernel::new(move |remote, _events| {
                client(remote, addr, username)
            }))
            .unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(90), async move {
            tokio::select! {
                res = server => Err(NetworkError::msg(format!("server ended: {:?}", res.map(|_| ())))),
                res = node => res.map(|_| ()),
            }
        })
        .await
        .expect("test timed out");
        outcome.expect("the registration is refused, then admitted at a lower level");
    }
}
