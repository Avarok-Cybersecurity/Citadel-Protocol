
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use uuid::Uuid;
    use lusna_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use lusna_sdk::prelude::{NodeBuilder, PeerChannel, NodeFuture, ConnectSuccess, NetKernel};
    use hyxe_net::prelude::{NetworkError, SecureProtocolPacket, SecBuffer, SessionSecuritySettingsBuilder, UdpMode, SecrecyMode, KemAlgorithm, EncryptionAlgorithm};
    use rstest::rstest;
    use tokio::sync::Barrier;
    use std::sync::Arc;
    use serde::{Serialize, Deserialize};
    use rand::prelude::ThreadRng;
    use rand::Rng;
    use futures::StreamExt;
    use hyxe_net::prelude::SyncIO;
    use std::net::SocketAddr;
    use lusna_sdk::prefabs::ClientServerRemote;
    use std::str::FromStr;
    use lusna_sdk::prefabs::server::client_connect_listener::ClientConnectListenerKernel;
    use std::future::Future;
    use parking_lot::Mutex;
    use std::time::Duration;
    use lusna_sdk::prefabs::client::PrefabFunctions;
    use lusna_sdk::prefabs::client::peer_connection::PeerConnectionKernel;
    use lusna_sdk::prefabs::server::empty::EmptyKernel;

    const MESSAGE_LEN: usize = 2000;

    #[derive(Serialize, Deserialize)]
    pub struct MessageTransfer {
        pub idx: u64,
        pub rand: Vec<u8>
    }

    impl MessageTransfer {
        pub fn create(idx: u64) -> SecureProtocolPacket {
            let mut rng = ThreadRng::default();
            let mut rand = vec![0u8; MESSAGE_LEN];
            rng.fill(rand.as_mut_slice());

            SecureProtocolPacket::from(Self { idx, rand }.serialize_to_vector().unwrap())
        }

        pub fn receive(input: SecBuffer) -> Self {
            Self::deserialize_from_vector(input.as_ref()).unwrap()
        }
    }

    pub fn server_info_reactive<F, Fut>(on_channel_received: F) -> (NodeFuture<Box<dyn NetKernel>>, SocketAddr)
        where
            F: Fn(ConnectSuccess, ClientServerRemote) -> Fut + Send + Sync + 'static,
            Fut: Future<Output=Result<(), NetworkError>> + Send + Sync + 'static {
        let port = portpicker::pick_unused_port().unwrap();
        let bind_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap();
        let server = lusna_sdk::test_common::server_test_node(bind_addr, Box::new(ClientConnectListenerKernel::new(on_channel_received)) as Box<dyn NetKernel>);
        (server, bind_addr)
    }

    pub fn server_info() -> (NodeFuture<EmptyKernel>, SocketAddr) {
        let port = portpicker::pick_unused_port().unwrap();
        let bind_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap();
        let server = lusna_sdk::test_common::server_test_node(bind_addr, EmptyKernel::default());
        (server, bind_addr)
    }

    async fn handle_send_receive(barrier: Arc<Barrier>, channel: PeerChannel, count: usize) -> Result<(), NetworkError> {
        let (tx, rx) = channel.split();

        for idx in 0..count {
            tx.send_message(MessageTransfer::create(idx as u64)).await?;
        }

        let mut cur_idx = 0usize;

        let mut rx = rx.take(count);
        while let Some(msg) = rx.next().await {
            log::info!("**~ Received message {} ~**", cur_idx);
            let msg = MessageTransfer::receive(msg);
            assert_eq!(msg.idx, cur_idx as u64);
            assert_eq!(msg.rand.len(), MESSAGE_LEN);
            cur_idx += 1;
        }

        assert_eq!(cur_idx as usize, count);
        let _ = barrier.wait().await;

        Ok(())
    }

    static BARRIER: Mutex<Option<Arc<Barrier>>> = parking_lot::const_mutex(None);

    fn setup_barrier(count: usize) {
        *BARRIER.lock() = Some(Arc::new(Barrier::new(count)))
    }

    fn get_barrier() -> Arc<Barrier> {
        BARRIER.lock().clone().unwrap()
    }

    #[rstest]
    #[case(500, SecrecyMode::Perfect)]
    #[case(4000, SecrecyMode::BestEffort)]
    #[tokio::test(flavor="multi_thread")]
    async fn stress_test_c2s_messaging(#[case] message_count: usize,
                                       #[case] secrecy_mode: SecrecyMode,
                                       #[values(KemAlgorithm::Firesaber, KemAlgorithm::Kyber768_90s)]
                                       kem: KemAlgorithm,
                                       #[values(EncryptionAlgorithm::AES_GCM_256_SIV, EncryptionAlgorithm::Xchacha20Poly_1305)]
                                       enx: EncryptionAlgorithm) {

        lusna_sdk::test_common::setup_log();
        static CLIENT_SUCCESS: AtomicBool = AtomicBool::new(false);
        static SERVER_SUCCESS: AtomicBool = AtomicBool::new(false);
        CLIENT_SUCCESS.store(false, Ordering::SeqCst);
        SERVER_SUCCESS.store(false, Ordering::SeqCst);

        setup_barrier(2);

        let (server, server_addr) = server_info_reactive(move |conn, remote| async move {
            log::info!("*** SERVER RECV CHANNEL ***");
            handle_send_receive(get_barrier(), conn.channel, message_count).await?;
            log::info!("***SERVER TEST SUCCESS***");
            SERVER_SUCCESS.store(true, Ordering::Relaxed);
            remote.shutdown_kernel().await
        });

        let uuid = Uuid::new_v4();
        let session_security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(secrecy_mode)
            .with_crypto_params(kem + enx)
            .build();

        let client_kernel = SingleClientServerConnectionKernel::new_passwordless(uuid, server_addr, UdpMode::Enabled,session_security,move |connection, remote| async move {
            log::info!("*** CLIENT RECV CHANNEL ***");
            handle_send_receive(get_barrier(), connection.channel, message_count).await?;
            log::info!("***CLIENT TEST SUCCESS***");
            CLIENT_SUCCESS.store(true, Ordering::Relaxed);
            remote.shutdown_kernel().await
        });

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        let _ = tokio::time::timeout(Duration::from_secs(120),joined).await.unwrap().unwrap();

        assert!(CLIENT_SUCCESS.load(Ordering::Relaxed));
        assert!(SERVER_SUCCESS.load(Ordering::Relaxed));
    }

    #[rstest]
    #[case(500, SecrecyMode::Perfect)]
    #[case(4000, SecrecyMode::BestEffort)]
    #[tokio::test(flavor="multi_thread")]
    async fn stress_test_p2p_messaging(#[case] message_count: usize,
                                       #[case] secrecy_mode: SecrecyMode,
                                       #[values(KemAlgorithm::Firesaber, KemAlgorithm::Kyber768_90s)]
                                       kem: KemAlgorithm,
                                       #[values(EncryptionAlgorithm::AES_GCM_256_SIV, EncryptionAlgorithm::Xchacha20Poly_1305)]
                                       enx: EncryptionAlgorithm) {

        lusna_sdk::test_common::setup_log();
        static CLIENT0_SUCCESS: AtomicBool = AtomicBool::new(false);
        static CLIENT1_SUCCESS: AtomicBool = AtomicBool::new(false);
        CLIENT0_SUCCESS.store(false, Ordering::SeqCst);
        CLIENT1_SUCCESS.store(false, Ordering::SeqCst);

        setup_barrier(2);

        let (server, server_addr) = server_info();

        let uuid0 = Uuid::new_v4();
        let uuid1 = Uuid::new_v4();
        let session_security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(secrecy_mode)
            .with_crypto_params(kem + enx)
            .build();

        // TODO: SinglePeerConnectionKernel
        // to not hold up all conns
        let client_kernel0 = PeerConnectionKernel::new_passwordless(uuid0, server_addr, vec![uuid1.into()],UdpMode::Enabled,session_security,move |mut connection, remote| async move {
            handle_send_receive(get_barrier(), connection.recv().await.unwrap()?.channel, message_count).await?;
            log::info!("***CLIENT0 TEST SUCCESS***");
            CLIENT0_SUCCESS.store(true, Ordering::Relaxed);
            remote.shutdown_kernel().await
        });

        let client_kernel1 = PeerConnectionKernel::new_passwordless(uuid1, server_addr, vec![uuid0.into()], UdpMode::Enabled,session_security,move |mut connection, remote| async move {
            handle_send_receive(get_barrier(), connection.recv().await.unwrap()?.channel, message_count).await?;
            log::info!("***CLIENT1 TEST SUCCESS***");
            CLIENT1_SUCCESS.store(true, Ordering::Relaxed);
            remote.shutdown_kernel().await
        });

        let client0 = NodeBuilder::default().build(client_kernel0).unwrap();
        let client1 = NodeBuilder::default().build(client_kernel1).unwrap();
        let clients = futures::future::try_join(client0, client1);

        let task = async move {
            tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = clients => client_res.map(|_| ())
            }
        };

        let _ = tokio::time::timeout(Duration::from_secs(120),task).await.unwrap().unwrap();

        assert!(CLIENT0_SUCCESS.load(Ordering::Relaxed));
        assert!(CLIENT1_SUCCESS.load(Ordering::Relaxed));
    }
}