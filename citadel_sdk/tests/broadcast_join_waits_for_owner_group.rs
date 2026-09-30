#![cfg(not(target_family = "wasm"))]
//! A `BroadcastKernel` joiner must join once the owner's group exists, however
//! late the owner creates it. The owner here accepts the joiner's registration
//! and then, before creating the group, stalls past the joiner's sleep-poll
//! window (checks at 0, 1, 3, 7 and 15 s, then a final 16 s sleep with no check).
//! The group exists at 20 s — while the joiner is still inside its own 31 s wait —
//! yet the joiner reports `BroadcastOwnerGroupMissing` and never joins.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::broadcast::{BroadcastKernel, GroupInitRequestType};
    use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers, TestBarrier};
    use citadel_types::proto::{GroupType, MessageGroupOptions};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use uuid::Uuid;

    // Injected owner stall: longer than the joiner's last check (15 s) and
    // shorter than the moment it gives up (31 s). Not a latency assertion — the
    // test asserts only that the join eventually happens.
    const OWNER_STALL_BEFORE_CREATE: Duration = Duration::from_secs(20);

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_joiner_joins_a_group_the_owner_creates_late(
    ) -> Result<(), Box<dyn std::error::Error>> {
        citadel_logging::setup_log();
        TestBarrier::setup(2);

        let joined = &AtomicBool::new(false);
        let (server, server_addr) = server_info::<StackedRatchet>();
        let owner_uuid = Uuid::new_v4();
        let joiner_uuid = Uuid::new_v4();
        let group_id = Uuid::new_v4();

        let owner_kernel = SingleClientServerConnectionKernel::new(
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, owner_uuid)
                .build()
                .unwrap(),
            move |connection| async move {
                let mut signals = connection
                    .remote
                    .get_unprocessed_signals_receiver()
                    .unwrap();
                wait_for_peers().await;

                while let Some(evt) = signals.recv().await {
                    if let NodeResult::PeerEvent(PeerEvent {
                        event: sig @ PeerSignal::PostRegister { .. },
                        ..
                    }) = evt
                    {
                        let _ =
                            citadel_sdk::responses::peer_register(sig, true, &connection.remote)
                                .await?;
                        break;
                    }
                }

                citadel_io::tokio::time::sleep(OWNER_STALL_BEFORE_CREATE).await;

                let _channel = connection
                    .create_group_with_options(
                        None,
                        MessageGroupOptions {
                            group_type: GroupType::Public,
                            id: group_id.as_u128(),
                            ..Default::default()
                        },
                    )
                    .await?;
                log::info!(target: "citadel", "owner created the group after its stall");

                wait_for_peers().await;
                connection.shutdown_kernel().await
            },
        );

        let joiner_kernel = BroadcastKernel::new(
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, joiner_uuid)
                .build()
                .unwrap(),
            GroupInitRequestType::Join {
                local_user: UserIdentifier::from(joiner_uuid),
                owner: owner_uuid.into(),
                group_id,
                do_peer_register: true,
            },
            move |channel, remote| async move {
                joined.store(true, Ordering::Relaxed);
                wait_for_peers().await;
                drop(channel);
                remote.shutdown_kernel().await
            },
        );

        let owner = DefaultNodeBuilder::default().build(owner_kernel).unwrap();
        let joiner = DefaultNodeBuilder::default().build(joiner_kernel).unwrap();

        let clients =
            Box::pin(async move { futures::future::try_join(owner, joiner).await.map(|_| ()) });

        if let Err(err) = futures::future::try_select(server, clients).await {
            return match err {
                futures::future::Either::Left(res) => Err(res.0.into_string().into()),
                futures::future::Either::Right(res) => Err(res.0.into_string().into()),
            };
        }

        assert!(joined.load(Ordering::Relaxed), "the joiner never joined");
        Ok(())
    }
}
