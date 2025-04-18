#[cfg(test)]
mod tests {
    use citadel_io::tokio;
    use citadel_io::tokio::sync::Barrier;
    use citadel_io::tokio::task::JoinError;
    use citadel_sdk::prefabs::client::broadcast::{BroadcastKernel, GroupInitRequestType};
    use citadel_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use citadel_sdk::prefabs::client::{
        DefaultServerConnectionSettingsBuilder, ServerConnectionSettingsBuilder,
    };
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, wait_for_peers};
    use citadel_types::crypto::{EncryptionAlgorithm, KemAlgorithm};
    use citadel_types::prelude::SecrecyMode;
    use futures::prelude::stream::FuturesUnordered;
    use futures::{StreamExt, TryStreamExt};
    use rand::prelude::ThreadRng;
    use rand::Rng;
    use rstest::rstest;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    struct TestSpawner {
        // this may not be a real localset
        #[cfg(not(feature = "multi-threaded"))]
        local_set: citadel_io::tokio::task::LocalSet,
        #[cfg_attr(feature = "multi-threaded", allow(dead_code))]
        #[cfg(feature = "multi-threaded")]
        local_set: (),
    }

    impl TestSpawner {
        pub fn new() -> Self {
            Self {
                local_set: Default::default(),
            }
        }

        #[cfg(not(feature = "multi-threaded"))]
        pub fn spawn<T>(
            &self,
            future: T,
        ) -> citadel_io::tokio::task::JoinHandle<<T as Future>::Output>
        where
            T: Future + 'static,
            T::Output: 'static,
        {
            self.local_set.spawn_local(future)
        }

        #[cfg(feature = "multi-threaded")]
        pub fn spawn<T>(
            &self,
            future: T,
        ) -> citadel_io::tokio::task::JoinHandle<<T as Future>::Output>
        where
            T: Future + Send + 'static,
            T::Output: Send + 'static,
        {
            citadel_io::tokio::task::spawn(future)
        }

        #[cfg(not(feature = "multi-threaded"))]
        pub async fn local_set(self) -> Result<(), JoinError> {
            self.local_set.await;
            Ok(())
        }

        #[cfg(feature = "multi-threaded")]
        pub async fn local_set(self) -> Result<(), JoinError> {
            Ok(())
        }
    }

    const MESSAGE_LEN: usize = 2000;

    #[derive(Serialize, Deserialize)]
    pub struct MessageTransfer {
        pub idx: u64,
        pub rand: Vec<u8>,
        pub checksum: u64,
    }

    impl MessageTransfer {
        pub fn create_secbuffer(idx: u64) -> SecBuffer {
            let rand = Self::create_rand(idx);
            rand.into()
        }

        fn create_rand(idx: u64) -> Vec<u8> {
            let mut rng = ThreadRng::default();
            let mut rand = vec![0u8; MESSAGE_LEN];
            rng.fill(rand.as_mut_slice());
            let rand_sum: u64 = rand.iter().copied().map(u64::from).sum();
            Self {
                idx,
                rand,
                checksum: rand_sum,
            }
            .serialize_to_vector()
            .unwrap()
        }

        pub fn receive(input: SecBuffer) -> Self {
            let this = Self::deserialize_from_vector(input.as_ref()).unwrap();
            // Not a real hash, just for testing purposes
            assert_eq!(
                this.checksum,
                this.rand.iter().copied().map(u64::from).sum::<u64>(),
                "Checksum mismatch"
            );
            this
        }
    }

    async fn handle_send_receive_e2e<R: Ratchet>(
        barrier: Arc<Barrier>,
        channel: PeerChannel<R>,
        count: usize,
    ) -> Result<(), NetworkError> {
        let (mut tx, rx) = channel.split();
        for idx in 0..count {
            tx.send(MessageTransfer::create_secbuffer(idx as u64))
                .await?;
        }

        let mut cur_idx = 0usize;
        let cid = rx.vconn_type.get_session_cid();

        let mut rx = rx.take(count);
        while let Some(msg) = rx.next().await {
            let msg = MessageTransfer::receive(msg);
            log::trace!(target: "citadel", "**~ Client {cid} Received message {} (expected: {})~**", msg.idx, cur_idx);
            assert_eq!(msg.idx, cur_idx as u64);
            assert_eq!(msg.rand.len(), MESSAGE_LEN);
            cur_idx += 1;
        }

        assert_eq!(cur_idx, count);
        let _ = barrier.wait().await;

        Ok(())
    }

    async fn handle_send_receive_group(
        barrier: Arc<Barrier>,
        channel: GroupChannel,
        count: usize,
        total_peers: usize,
    ) -> Result<(), NetworkError> {
        let _ = barrier.wait().await;
        let (tx, mut rx) = channel.split();

        for idx in 0..count {
            tx.send_message(MessageTransfer::create_secbuffer(idx as u64))
                .await?;
        }

        let mut counter = HashMap::new();

        while let Some(msg) = rx.next().await {
            match msg {
                GroupBroadcastPayload::Message { payload, sender } => {
                    let cur_idx = counter.entry(sender).or_insert(0usize);
                    log::trace!(target: "citadel", "**~ Received message {} for {}~**", cur_idx, sender);
                    let msg = MessageTransfer::receive(payload);
                    // order is not guaranteed in group broadcasts. Do not use idx
                    //assert_eq!(msg.idx, *cur_idx as u64);
                    assert_eq!(msg.rand.len(), MESSAGE_LEN);
                    *cur_idx += 1;
                    if counter.values().all(|r| *r == count) && counter.len() == total_peers - 1 {
                        break;
                    }
                }

                GroupBroadcastPayload::Event { payload } => {
                    if let GroupBroadcast::MessageResponse { .. } = &payload {
                    } else {
                        panic!("Received invalid message type: {payload:?}");
                    }
                }
            }
        }

        // we receive messages from n - 1 peers
        assert_eq!(counter.len(), total_peers - 1);
        for messages_received in counter.values() {
            assert_eq!(*messages_received, count);
        }

        let _ = barrier.wait().await;

        Ok(())
    }

    #[cfg(feature = "localhost-testing")]
    fn get_barrier() -> Arc<Barrier> {
        citadel_sdk::test_common::TEST_BARRIER
            .lock()
            .clone()
            .unwrap()
            .inner
    }

    #[cfg(not(feature = "localhost-testing"))]
    fn get_barrier() -> Arc<Barrier> {
        panic!("TestBarrier is not available without the localhost-testing feature");
    }

    #[rstest]
    #[case(500, SecrecyMode::Perfect)]
    #[case(500, SecrecyMode::BestEffort)]
    #[timeout(std::time::Duration::from_secs(240))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn stress_test_c2s_messaging(
        #[case] message_count: usize,
        #[case] secrecy_mode: SecrecyMode,
        #[values(KemAlgorithm::Kyber)] kem: KemAlgorithm,
        #[values(
            EncryptionAlgorithm::AES_GCM_256,
            EncryptionAlgorithm::ChaCha20Poly_1305,
            EncryptionAlgorithm::Ascon80pq
        )]
        enx: EncryptionAlgorithm,
    ) {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        static CLIENT_SUCCESS: AtomicBool = AtomicBool::new(false);
        static SERVER_SUCCESS: AtomicBool = AtomicBool::new(false);
        CLIENT_SUCCESS.store(false, Ordering::Relaxed);
        SERVER_SUCCESS.store(false, Ordering::Relaxed);

        let spawner = TestSpawner::new();

        let (server, server_addr) =
            citadel_sdk::test_common::server_info_reactive::<_, _, StackedRatchet>(
                move |mut connection| async move {
                    log::trace!(target: "citadel", "*** SERVER RECV CHANNEL ***");
                    handle_send_receive_e2e(
                        get_barrier(),
                        connection.take_channel().unwrap(),
                        message_count,
                    )
                    .await?;
                    log::trace!(target: "citadel", "***SERVER TEST SUCCESS***");
                    SERVER_SUCCESS.store(true, Ordering::Relaxed);
                    connection.shutdown_kernel().await
                },
                |_| {},
            );

        let uuid = Uuid::new_v4();
        let session_security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(secrecy_mode)
            .with_crypto_params(kem + enx)
            .build()
            .unwrap();

        let server_connection_settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                .with_udp_mode(UdpMode::Enabled)
                .with_session_security_settings(session_security)
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            move |mut connection| async move {
                log::trace!(target: "citadel", "*** CLIENT RECV CHANNEL ***");
                handle_send_receive_e2e(
                    get_barrier(),
                    connection.take_channel().unwrap(),
                    message_count,
                )
                .await?;
                log::trace!(target: "citadel", "***CLIENT TEST SUCCESS***");
                CLIENT_SUCCESS.store(true, Ordering::Relaxed);
                connection.shutdown_kernel().await
            },
        );

        let client = spawner.spawn(DefaultNodeBuilder::default().build(client_kernel).unwrap());
        let server = spawner.spawn(server);
        let maybe_localset = spawner.local_set();

        let joined = futures::future::try_join3(server, client, maybe_localset);

        let (_res0, _res1, _res3) = joined.await.unwrap();

        assert!(CLIENT_SUCCESS.load(Ordering::Relaxed));
        assert!(SERVER_SUCCESS.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(100, SecrecyMode::Perfect, None)]
    #[case(100, SecrecyMode::BestEffort, Some("test-password"))]
    #[timeout(std::time::Duration::from_secs(240))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn stress_test_c2s_messaging_kyber(
        #[case] message_count: usize,
        #[case] secrecy_mode: SecrecyMode,
        #[case] server_password: Option<&'static str>,
        #[values(KemAlgorithm::Kyber)] kem: KemAlgorithm,
        #[values(EncryptionAlgorithm::Kyber)] enx: EncryptionAlgorithm,
    ) {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        static CLIENT_SUCCESS: AtomicBool = AtomicBool::new(false);
        static SERVER_SUCCESS: AtomicBool = AtomicBool::new(false);
        CLIENT_SUCCESS.store(false, Ordering::Relaxed);
        SERVER_SUCCESS.store(false, Ordering::Relaxed);

        let spawner = TestSpawner::new();

        let (server, server_addr) =
            citadel_sdk::test_common::server_info_reactive::<_, _, StackedRatchet>(
                move |mut connection| async move {
                    log::trace!(target: "citadel", "*** SERVER RECV CHANNEL ***");
                    handle_send_receive_e2e(
                        get_barrier(),
                        connection.take_channel().unwrap(),
                        message_count,
                    )
                    .await?;
                    log::trace!(target: "citadel", "***SERVER TEST SUCCESS***");
                    SERVER_SUCCESS.store(true, Ordering::Relaxed);
                    connection.shutdown_kernel().await
                },
                |node| {
                    if let Some(password) = server_password {
                        node.with_server_password(password);
                    }
                },
            );

        let uuid = Uuid::new_v4();
        let session_security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(secrecy_mode)
            .with_crypto_params(kem + enx + SigAlgorithm::Falcon1024)
            .build()
            .unwrap();

        let mut connection_settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                .with_udp_mode(UdpMode::Enabled)
                .with_session_security_settings(session_security);

        if let Some(password) = server_password {
            connection_settings = connection_settings.with_session_password(password);
        }

        let connection_settings = connection_settings.build().unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            connection_settings,
            move |mut connection| async move {
                log::trace!(target: "citadel", "*** CLIENT RECV CHANNEL ***");
                handle_send_receive_e2e(
                    get_barrier(),
                    connection.take_channel().unwrap(),
                    message_count,
                )
                .await?;
                log::trace!(target: "citadel", "***CLIENT TEST SUCCESS***");
                CLIENT_SUCCESS.store(true, Ordering::Relaxed);
                connection.shutdown_kernel().await
            },
        );

        let client = spawner.spawn(DefaultNodeBuilder::default().build(client_kernel).unwrap());
        let server = spawner.spawn(server);
        let maybe_local_set = spawner.local_set();

        let joined = futures::future::try_join3(server, client, maybe_local_set);

        let (_res0, _res1, _res2) = joined.await.unwrap();

        assert!(CLIENT_SUCCESS.load(Ordering::Relaxed));
        assert!(SERVER_SUCCESS.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(500, SecrecyMode::Perfect, None)]
    #[case(500, SecrecyMode::BestEffort, Some("test-p2p-password"))]
    #[timeout(std::time::Duration::from_secs(240))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn stress_test_p2p_messaging(
        #[case] message_count: usize,
        #[case] secrecy_mode: SecrecyMode,
        #[case] p2p_password: Option<&'static str>,
        #[values(KemAlgorithm::Kyber)] kem: KemAlgorithm,
        #[values(
            EncryptionAlgorithm::AES_GCM_256,
            EncryptionAlgorithm::ChaCha20Poly_1305,
            EncryptionAlgorithm::Ascon80pq
        )]
        enx: EncryptionAlgorithm,
    ) {
        stress_test_p2p_messaging_with_ratchet::<StackedRatchet>(
            message_count,
            secrecy_mode,
            p2p_password,
            kem,
            enx,
        )
        .await;
    }

    #[rstest]
    #[timeout(std::time::Duration::from_secs(240))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn stress_test_p2p_messaging_thin_ratchet() {
        stress_test_p2p_messaging_with_ratchet::<MonoRatchet>(
            500,
            SecrecyMode::Perfect,
            None,
            KemAlgorithm::Kyber,
            EncryptionAlgorithm::AES_GCM_256,
        )
        .await;
    }

    async fn stress_test_p2p_messaging_with_ratchet<R: Ratchet>(
        message_count: usize,
        secrecy_mode: SecrecyMode,
        p2p_password: Option<&'static str>,
        kem: KemAlgorithm,
        enx: EncryptionAlgorithm,
    ) {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(2);
        let client0_success = &AtomicBool::new(false);
        let client1_success = &AtomicBool::new(false);

        let (server, server_addr) = server_info::<R>();

        let uuid0 = Uuid::new_v4();
        let uuid1 = Uuid::new_v4();
        let session_security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(secrecy_mode)
            .with_crypto_params(kem + enx)
            .build()
            .unwrap();

        let mut peer0_agg = PeerConnectionSetupAggregator::default()
            .with_peer_custom(uuid1)
            .with_session_security_settings(session_security);

        if let Some(password) = p2p_password {
            peer0_agg = peer0_agg.with_session_password(password);
        }

        let peer0_connection = peer0_agg.add();

        let mut peer1_agg = PeerConnectionSetupAggregator::default()
            .with_peer_custom(uuid0)
            .with_session_security_settings(session_security);

        if let Some(password) = p2p_password {
            peer1_agg = peer1_agg.with_session_password(password);
        }

        let peer1_connection = peer1_agg.add();

        let server_connection_settings =
            ServerConnectionSettingsBuilder::<R, _>::transient_with_id(server_addr, uuid0)
                .with_udp_mode(UdpMode::Enabled)
                .with_session_security_settings(session_security)
                .build()
                .unwrap();

        let client_kernel0 = PeerConnectionKernel::new(
            server_connection_settings,
            peer0_connection,
            move |mut connection, remote| async move {
                handle_send_receive_e2e(
                    get_barrier(),
                    connection.recv().await.unwrap()?.channel,
                    message_count,
                )
                .await?;
                log::trace!(target: "citadel", "***CLIENT0 TEST SUCCESS***");
                client0_success.store(true, Ordering::Relaxed);
                remote.shutdown_kernel().await
            },
        );

        let server_connection_settings =
            ServerConnectionSettingsBuilder::<R, _>::transient_with_id(server_addr, uuid1)
                .with_udp_mode(UdpMode::Enabled)
                .with_session_security_settings(session_security)
                .build()
                .unwrap();

        let client_kernel1 = PeerConnectionKernel::new(
            server_connection_settings,
            peer1_connection,
            move |mut connection, remote| async move {
                handle_send_receive_e2e(
                    get_barrier(),
                    connection.recv().await.unwrap()?.channel,
                    message_count,
                )
                .await?;
                log::trace!(target: "citadel", "***CLIENT1 TEST SUCCESS***");
                client1_success.store(true, Ordering::Relaxed);
                remote.shutdown_kernel().await
            },
        );

        let client0 = NodeBuilder::default().build(client_kernel0).unwrap();
        let client1 = NodeBuilder::default().build(client_kernel1).unwrap();
        let clients = futures::future::try_join(client0, client1);

        let task = async move {
            citadel_io::tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = clients => client_res.map(|_| ())
            }
        };

        let _ = citadel_io::tokio::time::timeout(Duration::from_secs(120), task)
            .await
            .unwrap();

        assert!(client0_success.load(Ordering::Relaxed));
        assert!(client1_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(500, 3)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn stress_test_group_broadcast(#[case] message_count: usize, #[case] peer_count: usize) {
        citadel_logging::setup_log();
        citadel_sdk::test_common::TestBarrier::setup(peer_count);

        static CLIENT_SUCCESS: AtomicUsize = AtomicUsize::new(0);
        CLIENT_SUCCESS.store(0, Ordering::Relaxed);
        let (server, server_addr) = server_info::<StackedRatchet>();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count)
            .map(|_| Uuid::new_v4())
            .collect::<Vec<Uuid>>();
        let group_id = Uuid::new_v4();

        for idx in 0..peer_count {
            let uuid = total_peers.get(idx).cloned().unwrap();
            let owner = total_peers.first().cloned().unwrap().into();

            let request = if idx == 0 {
                // invite list is empty since we will expect the users to post_register to us before attempting to join
                GroupInitRequestType::Create {
                    local_user: UserIdentifier::from(uuid),
                    invite_list: vec![],
                    group_id,
                    accept_registrations: true,
                }
            } else {
                GroupInitRequestType::Join {
                    local_user: UserIdentifier::from(uuid),
                    owner,
                    group_id,
                    do_peer_register: true,
                }
            };

            let server_connection_settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                    .build()
                    .unwrap();

            let client_kernel = BroadcastKernel::new(
                server_connection_settings,
                request,
                move |channel, remote| async move {
                    log::trace!(target: "citadel", "***GROUP PEER {}={} CONNECT SUCCESS***", idx,uuid);
                    wait_for_peers().await;
                    // wait for every group member to connect to ensure all receive all messages
                    handle_send_receive_group(get_barrier(), channel, message_count, peer_count)
                        .await?;
                    wait_for_peers().await;
                    let _ = CLIENT_SUCCESS.fetch_add(1, Ordering::Relaxed);
                    remote.shutdown_kernel().await
                },
            );

            let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
            let task = async move { client.await.map(|_| ()) };

            client_kernels.push(task);
        }

        let clients = Box::pin(async move { client_kernels.try_collect::<()>().await.map(|_| ()) });

        let res = futures::future::try_select(server, clients).await;
        if let Err(err) = &res {
            match err {
                futures::future::Either::Left(left) => {
                    log::warn!(target: "citadel", "ERR-left: {:?}", &left.0);
                }

                futures::future::Either::Right(right) => {
                    log::warn!(target: "citadel", "ERR-right: {:?}", &right.0);
                }
            }
        }
        assert!(res.is_ok());
        assert_eq!(CLIENT_SUCCESS.load(Ordering::Relaxed), peer_count);
    }
}
