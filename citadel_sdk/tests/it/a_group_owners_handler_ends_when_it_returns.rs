//! A group owner that accepts registrations ends when its handler returns.
//!
//! The owner's handler ran joined with the task that accepts registrations, which never ends on
//! its own, so the kernel's start never returned. Test builds hid it: there the acceptor stopped
//! after a fixed number of registrations. Here the owner's handler returns at once, with nobody
//! registering, and the kernel's start must return.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::broadcast::{BroadcastKernel, GroupInitRequestType};
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, TestBarrier};
    use std::time::Duration;
    use uuid::Uuid;

    /// Shuts the node down once the wrapped kernel's start has returned, so the node finishing
    /// is evidence that it did.
    struct EndsAfterStart<K> {
        inner: K,
        remote: Option<NodeRemote<StackedRatchet>>,
    }

    #[async_trait]
    impl<K: NetKernel<StackedRatchet>> NetKernel<StackedRatchet> for EndsAfterStart<K> {
        fn load_remote(&mut self, remote: NodeRemote<StackedRatchet>) -> Result<(), NetworkError> {
            self.remote = Some(remote.clone());
            self.inner.load_remote(remote)
        }

        async fn on_start(&self) -> Result<(), NetworkError> {
            self.inner.on_start().await?;
            self.remote.as_ref().expect("loaded").shutdown().await
        }

        async fn on_node_event_received(
            &self,
            message: NodeResult<StackedRatchet>,
        ) -> Result<(), NetworkError> {
            self.inner.on_node_event_received(message).await
        }

        async fn on_stop(&mut self) -> Result<(), NetworkError> {
            self.inner.on_stop().await
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_owner_accepting_registrations_ends_when_its_handler_returns() {
        citadel_logging::setup_log();
        TestBarrier::setup(1);
        let (server, server_addr) = server_info::<StackedRatchet>();
        let owner = Uuid::new_v4();
        let settings = DefaultServerConnectionSettingsBuilder::transient_with_id(
            server_addr,
            owner,
            CertVerification::SelfSignedAccepted,
        )
        .build()
        .unwrap();
        let kernel = BroadcastKernel::<_, _, StackedRatchet>::new(
            settings,
            GroupInitRequestType::Create {
                local_user: UserIdentifier::from(owner),
                invite_list: vec![],
                group_id: Uuid::new_v4(),
                accept_registrations: true,
            },
            |channel, _connection| async move {
                drop(channel);
                Ok(())
            },
        );
        let client = citadel_sdk::test_common::node_builder()
            .with_link_manager(LinkManagerMode::Legacy)
            .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
            .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
            .build(EndsAfterStart {
                inner: kernel,
                remote: None,
            })
            .unwrap();
        // An upper bound only: the owner's node finishes as soon as its handler has returned.
        let outcome = tokio::time::timeout(Duration::from_secs(60), async move {
            tokio::select! {
                res = server => Err(format!("the server ended first: {:?}", res.map(|_| ()))),
                res = client => res.map(|_| ()).map_err(|err| err.into_string()),
            }
        })
        .await
        .expect("the owner's kernel did not return after its handler did");
        assert!(outcome.is_ok(), "{outcome:?}");
    }
}
