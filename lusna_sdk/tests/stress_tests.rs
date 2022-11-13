#[cfg(test)]
mod tests {
    use futures::prelude::stream::FuturesUnordered;
    use futures::{StreamExt, TryStreamExt};
    use hyxe_net::prelude::SyncIO;
    use hyxe_net::prelude::{
        EncryptionAlgorithm, KemAlgorithm, NetworkError, SecBuffer, SecrecyMode,
        SecureProtocolPacket, SessionSecuritySettingsBuilder, UdpMode,
    };
    use lusna_sdk::prefabs::client::broadcast::{BroadcastKernel, GroupInitRequestType};
    use lusna_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use lusna_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use lusna_sdk::prefabs::client::PrefabFunctions;
    use lusna_sdk::prelude::*;
    use lusna_sdk::test_common::server_info;
    use rand::prelude::ThreadRng;
    use rand::Rng;
    use rstest::rstest;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Barrier;
    use uuid::Uuid;

    const MESSAGE_LEN: usize = 2000;

    #[derive(Serialize, Deserialize)]
    pub struct MessageTransfer {
        pub idx: u64,
        pub rand: Vec<u8>,
    }

    impl MessageTransfer {
        pub fn create(idx: u64) -> SecureProtocolPacket {
            let rand = Self::create_rand(idx);
            rand.into()
        }

        pub fn create_secbuffer(idx: u64) -> SecBuffer {
            let rand = Self::create_rand(idx);
            rand.into()
        }

        fn create_rand(idx: u64) -> Vec<u8> {
            let mut rng = ThreadRng::default();
            let mut rand = vec![0u8; MESSAGE_LEN];
            rng.fill(rand.as_mut_slice());
            Self { idx, rand }.serialize_to_vector().unwrap()
        }

        pub fn receive(input: SecBuffer) -> Self {
            Self::deserialize_from_vector(input.as_ref()).unwrap()
        }
    }

    async fn handle_send_receive_e2e(
        barrier: Arc<Barrier>,
        channel: PeerChannel,
        count: usize,
    ) -> Result<(), NetworkError> {
        let (tx, rx) = channel.split();

        for idx in 0..count {
            tx.send_message(MessageTransfer::create(idx as u64)).await?;
        }

        let mut cur_idx = 0usize;

        let mut rx = rx.take(count);
        while let Some(msg) = rx.next().await {
            log::trace!(target: "lusna", "**~ Received message {} ~**", cur_idx);
            let msg = MessageTransfer::receive(msg);
            assert_eq!(msg.idx, cur_idx as u64);
            assert_eq!(msg.rand.len(), MESSAGE_LEN);
            cur_idx += 1;
        }

        assert_eq!(cur_idx as usize, count);
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
                    log::trace!(target: "lusna", "**~ Received message {} for {}~**", cur_idx, sender);
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
                    if let GroupBroadcast::MessageResponse(..) = &payload {
                    } else {
                        panic!("Received invalid message type: {:?}", payload);
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

    fn get_barrier() -> Arc<Barrier> {
        lusna_sdk::test_common::TEST_BARRIER
            .lock()
            .clone()
            .unwrap()
            .inner
    }

    #[rstest]
    #[case(500, SecrecyMode::Perfect)]
    #[case(500, SecrecyMode::BestEffort)]
    #[timeout(std::time::Duration::from_secs(240))]
    #[tokio::test(flavor = "multi_thread")]
    async fn stress_test_c2s_messaging(
        #[case] message_count: usize,
        #[case] secrecy_mode: SecrecyMode,
        #[values(KemAlgorithm::Kyber, KemAlgorithm::Kyber768)] kem: KemAlgorithm,
        #[values(
            EncryptionAlgorithm::AES_GCM_256_SIV,
            EncryptionAlgorithm::Xchacha20Poly_1305
        )]
        enx: EncryptionAlgorithm,
    ) {
        let _ = lusna_logging::setup_log();
        lusna_sdk::test_common::TestBarrier::setup(2);
        static CLIENT_SUCCESS: AtomicBool = AtomicBool::new(false);
        static SERVER_SUCCESS: AtomicBool = AtomicBool::new(false);
        CLIENT_SUCCESS.store(false, Ordering::Relaxed);
        SERVER_SUCCESS.store(false, Ordering::Relaxed);

        let (server, server_addr) = lusna_sdk::test_common::server_info_reactive(
            move |conn, remote| async move {
                log::trace!(target: "lusna", "*** SERVER RECV CHANNEL ***");
                handle_send_receive_e2e(get_barrier(), conn.channel, message_count).await?;
                log::trace!(target: "lusna", "***SERVER TEST SUCCESS***");
                SERVER_SUCCESS.store(true, Ordering::Relaxed);
                remote.shutdown_kernel().await
            },
            |_| {},
        );

        let uuid = Uuid::new_v4();
        let session_security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(secrecy_mode)
            .with_crypto_params(kem + enx)
            .build();

        let client_kernel = SingleClientServerConnectionKernel::new_passwordless(
            uuid,
            server_addr,
            UdpMode::Enabled,
            session_security,
            move |connection, remote| async move {
                log::trace!(target: "lusna", "*** CLIENT RECV CHANNEL ***");
                handle_send_receive_e2e(get_barrier(), connection.channel, message_count).await?;
                log::trace!(target: "lusna", "***CLIENT TEST SUCCESS***");
                CLIENT_SUCCESS.store(true, Ordering::Relaxed);
                remote.shutdown_kernel().await
            },
        );

        let client = tokio::spawn(NodeBuilder::default().build(client_kernel).unwrap());
        let server = tokio::spawn(server);

        let joined = futures::future::try_join(server, client);

        let (_res0, _res1) = joined.await.unwrap();

        assert!(CLIENT_SUCCESS.load(Ordering::Relaxed));
        assert!(SERVER_SUCCESS.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(500, SecrecyMode::Perfect)]
    #[case(500, SecrecyMode::BestEffort)]
    #[timeout(std::time::Duration::from_secs(240))]
    #[tokio::test(flavor = "multi_thread")]
    async fn stress_test_c2s_messaging_kyber(
        #[case] message_count: usize,
        #[case] secrecy_mode: SecrecyMode,
        #[values(KemAlgorithm::Kyber)] kem: KemAlgorithm,
        #[values(EncryptionAlgorithm::Kyber)] enx: EncryptionAlgorithm,
    ) {
        let _ = lusna_logging::setup_log();
        lusna_sdk::test_common::TestBarrier::setup(2);
        static CLIENT_SUCCESS: AtomicBool = AtomicBool::new(false);
        static SERVER_SUCCESS: AtomicBool = AtomicBool::new(false);
        CLIENT_SUCCESS.store(false, Ordering::Relaxed);
        SERVER_SUCCESS.store(false, Ordering::Relaxed);

        let (server, server_addr) = lusna_sdk::test_common::server_info_reactive(
            move |conn, remote| async move {
                log::trace!(target: "lusna", "*** SERVER RECV CHANNEL ***");
                handle_send_receive_e2e(get_barrier(), conn.channel, message_count).await?;
                log::trace!(target: "lusna", "***SERVER TEST SUCCESS***");
                SERVER_SUCCESS.store(true, Ordering::Relaxed);
                remote.shutdown_kernel().await
            },
            |_| {},
        );

        let uuid = Uuid::new_v4();
        let session_security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(secrecy_mode)
            .with_crypto_params(kem + enx)
            .build();

        let client_kernel = SingleClientServerConnectionKernel::new_passwordless(
            uuid,
            server_addr,
            UdpMode::Enabled,
            session_security,
            move |connection, remote| async move {
                log::trace!(target: "lusna", "*** CLIENT RECV CHANNEL ***");
                handle_send_receive_e2e(get_barrier(), connection.channel, message_count).await?;
                log::trace!(target: "lusna", "***CLIENT TEST SUCCESS***");
                CLIENT_SUCCESS.store(true, Ordering::Relaxed);
                remote.shutdown_kernel().await
            },
        );

        let client = tokio::spawn(NodeBuilder::default().build(client_kernel).unwrap());
        let server = tokio::spawn(server);

        let joined = futures::future::try_join(server, client);

        let (_res0, _res1) = joined.await.unwrap();

        assert!(CLIENT_SUCCESS.load(Ordering::Relaxed));
        assert!(SERVER_SUCCESS.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(500, SecrecyMode::Perfect)]
    #[case(500, SecrecyMode::BestEffort)]
    #[timeout(std::time::Duration::from_secs(240))]
    #[tokio::test(flavor = "multi_thread")]
    async fn stress_test_p2p_messaging(
        #[case] message_count: usize,
        #[case] secrecy_mode: SecrecyMode,
        #[values(KemAlgorithm::Kyber, KemAlgorithm::Kyber768)] kem: KemAlgorithm,
        #[values(
            EncryptionAlgorithm::AES_GCM_256_SIV,
            EncryptionAlgorithm::Xchacha20Poly_1305
        )]
        enx: EncryptionAlgorithm,
    ) {
        let _ = lusna_logging::setup_log();
        lusna_sdk::test_common::TestBarrier::setup(2);
        let client0_success = &AtomicBool::new(false);
        let client1_success = &AtomicBool::new(false);

        let (server, server_addr) = server_info();

        let uuid0 = Uuid::new_v4();
        let uuid1 = Uuid::new_v4();
        let session_security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(secrecy_mode)
            .with_crypto_params(kem + enx)
            .build();

        // TODO: SinglePeerConnectionKernel
        // to not hold up all conns
        let client_kernel0 = PeerConnectionKernel::new_passwordless(
            uuid0,
            server_addr,
            vec![uuid1.into()],
            UdpMode::Enabled,
            session_security,
            move |mut connection, remote| async move {
                handle_send_receive_e2e(
                    get_barrier(),
                    connection.recv().await.unwrap()?.channel,
                    message_count,
                )
                .await?;
                log::trace!(target: "lusna", "***CLIENT0 TEST SUCCESS***");
                client0_success.store(true, Ordering::Relaxed);
                remote.shutdown_kernel().await
            },
        );

        let client_kernel1 = PeerConnectionKernel::new_passwordless(
            uuid1,
            server_addr,
            vec![uuid0.into()],
            UdpMode::Enabled,
            session_security,
            move |mut connection, remote| async move {
                handle_send_receive_e2e(
                    get_barrier(),
                    connection.recv().await.unwrap()?.channel,
                    message_count,
                )
                .await?;
                log::trace!(target: "lusna", "***CLIENT1 TEST SUCCESS***");
                client1_success.store(true, Ordering::Relaxed);
                remote.shutdown_kernel().await
            },
        );

        let client0 = NodeBuilder::default().build(client_kernel0).unwrap();
        let client1 = NodeBuilder::default().build(client_kernel1).unwrap();
        let clients = futures::future::try_join(client0, client1);

        let task = async move {
            tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = clients => client_res.map(|_| ())
            }
        };

        let _ = tokio::time::timeout(Duration::from_secs(120), task)
            .await
            .unwrap();

        assert!(client0_success.load(Ordering::Relaxed));
        assert!(client1_success.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(500, 3)]
    #[timeout(std::time::Duration::from_secs(240))]
    #[tokio::test(flavor = "multi_thread")]
    async fn stress_test_group_broadcast(#[case] message_count: usize, #[case] peer_count: usize) {
        let _ = lusna_logging::setup_log();
        lusna_sdk::test_common::TestBarrier::setup(peer_count);

        static CLIENT_SUCCESS: AtomicUsize = AtomicUsize::new(0);
        CLIENT_SUCCESS.store(0, Ordering::Relaxed);
        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count)
            .into_iter()
            .map(|_| Uuid::new_v4())
            .collect::<Vec<Uuid>>();
        let group_id = Uuid::new_v4();

        for idx in 0..peer_count {
            let uuid = total_peers.get(idx).cloned().unwrap();
            let owner = total_peers.get(0).cloned().unwrap().into();

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

            let client_kernel = BroadcastKernel::new_passwordless_defaults(
                uuid,
                server_addr,
                request,
                move |channel, remote| async move {
                    log::trace!(target: "lusna", "***GROUP PEER {}={} CONNECT SUCCESS***", idx,uuid);
                    // wait for every group member to connect to ensure all receive all messages
                    handle_send_receive_group(get_barrier(), channel, message_count, peer_count)
                        .await?;
                    let _ = CLIENT_SUCCESS.fetch_add(1, Ordering::Relaxed);
                    remote.shutdown_kernel().await
                },
            );

            let client = NodeBuilder::default().build(client_kernel).unwrap();
            let task = async move { client.await.map(|_| ()) };

            client_kernels.push(task);
        }

        let clients = Box::pin(async move { client_kernels.try_collect::<()>().await.map(|_| ()) });

        let res = futures::future::try_select(server, clients).await;
        if let Err(err) = &res {
            match err {
                futures::future::Either::Left(left) => {
                    log::warn!(target: "lusna", "ERR-left: {:?}", &left.0);
                }

                futures::future::Either::Right(right) => {
                    log::warn!(target: "lusna", "ERR-right: {:?}", &right.0);
                }
            }
        }
        assert!(res.is_ok());
        assert_eq!(CLIENT_SUCCESS.load(Ordering::Relaxed), peer_count);
    }
}
