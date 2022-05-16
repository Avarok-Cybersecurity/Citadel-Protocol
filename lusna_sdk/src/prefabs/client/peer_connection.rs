use std::marker::PhantomData;
use crate::prelude::{NodeRemote, SessionSecuritySettings, UdpMode, NetworkError, SecBuffer, NetKernel, ConnectSuccess, HdpServerResult, ProtocolRemoteExt, UserIdentifier, ProtocolRemoteTargetExt};
use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
use crate::prelude::results::PeerConnectSuccess;
use futures::{Future, StreamExt};
use std::net::SocketAddr;
use crate::prefabs::ClientServerRemote;
use hyxe_net::re_imports::async_trait;
use futures::stream::FuturesUnordered;
use std::sync::Arc;
use uuid::Uuid;

/// A kernel that connects with the given credentials. If the credentials are not yet registered, then the [`Self::new_register`] function may be used, which will register the account before connecting.
/// This kernel will only allow outbound communication for the provided account
///
/// After establishing a connection to the central node, this kernel then begins connecting to the desired
/// peer(s)
pub struct PeerConnectionKernel<F, Fut> {
    inner_kernel: Box<dyn NetKernel>,
    // by using fn() -> Fut, the future does not need to be Sync
    _pd: PhantomData<fn() -> (F, Fut)>
}

#[async_trait]
impl<F, Fut> NetKernel for PeerConnectionKernel<F, Fut>
    where
        F: FnOnce(Vec<Result<PeerConnectSuccess, NetworkError>>, ClientServerRemote) -> Fut + Send + 'static,
        Fut: Future<Output=Result<(), NetworkError>> + Send + 'static {
    fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
        self.inner_kernel.load_remote(server_remote)
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        self.inner_kernel.on_start().await
    }

    async fn on_node_event_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
        self.inner_kernel.on_node_event_received(message).await
    }

    async fn on_stop(self) -> Result<(), NetworkError> {
        Ok(())
    }
}

pub struct PeerIDAggregator {
    inner: Vec<UserIdentifier>
}

impl PeerIDAggregator {
    pub fn new() -> Self {
        Self { inner: vec![] }
    }

    pub fn add<T: Into<UserIdentifier>>(mut self, peer: T) -> Self {
        self.inner.push(peer.into());
        self
    }

    pub fn finish(self) -> Vec<UserIdentifier> {
        self.inner
    }
}

impl<F, Fut> PeerConnectionKernel<F, Fut>
    where
        F: FnOnce(Vec<Result<PeerConnectSuccess, NetworkError>>, ClientServerRemote) -> Fut + Send + 'static,
        Fut: Future<Output=Result<(), NetworkError>> + Send + 'static {
    /// Creates a new connection with a central server entailed by the user information
    pub fn new_connect<T: Into<String>, P: Into<SecBuffer>>(username: T, password: P, peers: Vec<UserIdentifier>, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: F) -> Self {
        let server_conn_kernel = SingleClientServerConnectionKernel::new_connect(username, password, udp_mode, session_security_settings, |connect_success, remote| async move {
            on_server_connect_success(connect_success, remote, on_channel_received, peers).await
        });

        Self {
            inner_kernel: Box::new(server_conn_kernel),
            _pd: Default::default()
        }
    }

    /// Crates a new connection with a central server entailed by the user information and default configuration
    pub fn new_connect_defaults<T: Into<String>, P: Into<SecBuffer>>(username: T, password: P, peers: Vec<UserIdentifier>, on_channel_received: F) -> Self {
        Self::new_connect(username, password, peers, Default::default(), Default::default(), on_channel_received)
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with custom parameters
    pub fn new_register<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(full_name: T, username: R, password: P, peers: Vec<UserIdentifier>, server_addr: SocketAddr, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: F) -> Self {
        let server_conn_kernel = SingleClientServerConnectionKernel::new_register(full_name, username, password, server_addr, udp_mode, session_security_settings, |connect_success, remote| async move {
            on_server_connect_success(connect_success, remote, on_channel_received, peers).await
        });

        Self {
            inner_kernel: Box::new(server_conn_kernel),
            _pd: Default::default()
        }
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with default parameters
    pub fn new_register_defaults<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(full_name: T, username: R, password: P, peers: Vec<UserIdentifier>, server_addr: SocketAddr, on_channel_received: F) -> Self {
        Self::new_register(full_name, username, password, peers, server_addr, Default::default(), Default::default(), on_channel_received)
    }

    /// Creates a new authless connection with custom arguments
    pub fn new_passwordless(uuid: Uuid, server_addr: SocketAddr, peers: Vec<UserIdentifier>, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: F) -> Self {
        let server_conn_kernel = SingleClientServerConnectionKernel::new_passwordless(uuid, server_addr, udp_mode, session_security_settings,  |connect_success, remote| async move {
            on_server_connect_success(connect_success, remote, on_channel_received, peers).await
        });

        Self {
            inner_kernel: Box::new(server_conn_kernel),
            _pd: Default::default()
        }
    }

    /// Creates a new authless connection with default arguments
    pub fn new_passwordless_defaults(uuid: Uuid, server_addr: SocketAddr, peers: Vec<UserIdentifier>, on_channel_received: F) -> Self {
        Self::new_passwordless(uuid, server_addr, peers, Default::default(), Default::default(), on_channel_received)
    }
}

async fn on_server_connect_success<F, Fut>(connect_success: ConnectSuccess, cls_remote: ClientServerRemote, f: F, peers_to_connect: Vec<UserIdentifier>) -> Result<(), NetworkError>
    where F: FnOnce(Vec<Result<PeerConnectSuccess, NetworkError>>, ClientServerRemote) -> Fut + Send + 'static,
          Fut: Future<Output=Result<(), NetworkError>> + Send + 'static {

    let implicated_cid = connect_success.cid;
    let mut peers_already_registered = vec![];

    wait_for_peers().await;

    for peer in &peers_to_connect {
        // TODO: optimize this into a single operation
        peers_already_registered.push(peer.search_peer(implicated_cid, cls_remote.inner.account_manager()).await?)
    }

    let remote = cls_remote.inner.clone();
    let requests = FuturesUnordered::new();

    for (mutually_registered, peer_to_connect) in peers_already_registered.into_iter().zip(peers_to_connect) {
        // each task will be responsible for possibly registering to and connecting
        // with the desired peer
        let mut remote = remote.clone();
        let task = async move {
            if let Some(_already_registered) = mutually_registered {
                let mut handle = remote.find_target(implicated_cid, peer_to_connect).await?;
                handle.connect_to_peer().await
            } else {
                // do both register + connect
                // TODO: optimize peer registration + connection in one go
                let mut handle = remote.propose_target(implicated_cid, peer_to_connect.clone()).await?;
                let _reg_success = handle.register_to_peer().await?;
                log::info!("Peer {:?} registered || success -> now connecting", peer_to_connect);
                handle.connect_to_peer().await
            }
        };

        requests.push(Box::pin(task))
    }


    let results = requests.collect::<Vec<Result<PeerConnectSuccess, NetworkError>>>().await;
    (f)(results, cls_remote).await
}

#[cfg(test)]
async fn wait_for_peers() {
    let barrier = {
        TEST_BARRIER.lock().clone()
    };

    if let Some(test_barrier) = barrier {
        // wait for all peers to reach this point in the code
        test_barrier.wait().await;
    }
}

#[cfg(not(test))]
async fn wait_for_peers() {}

#[cfg(test)]
static TEST_BARRIER: parking_lot::Mutex<Option<TestBarrier>> = parking_lot::const_mutex(None);

#[derive(Clone)]
struct TestBarrier {
    inner: Arc<tokio::sync::Barrier>
}

impl TestBarrier {
    #[cfg(test)]
    pub fn setup(count: usize) {
        let _ = TEST_BARRIER.lock().replace(Self::new(count));
    }
    fn new(count: usize) -> Self {
        Self { inner: Arc::new(tokio::sync::Barrier::new(count)) }
    }

    pub async fn wait(&self) {
        let _ = self.inner.wait().await;
    }
}


#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::sync::atomic::{Ordering, AtomicUsize};
    use crate::test_common::{PEERS, server_info};
    use rstest::rstest;
    use crate::prefabs::client::peer_connection::{PeerConnectionKernel, TestBarrier, wait_for_peers};
    use futures::stream::FuturesUnordered;
    use futures::TryStreamExt;
    use uuid::Uuid;

    #[rstest]
    #[case(2)]
    #[case(3)]
    #[tokio::test]
    async fn peer_to_peer_connect(#[case] peer_count: usize) {
        assert!(peer_count > 1);
        crate::test_common::setup_log();
        TestBarrier::setup(peer_count);

        static CLIENT_SUCCESS: AtomicUsize = AtomicUsize::new(0);
        CLIENT_SUCCESS.store(0, Ordering::Relaxed);
        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count).into_iter().map(|idx| PEERS.get(idx).unwrap().0.clone()).collect::<Vec<String>>();
        
        for idx in 0..peer_count {
            let (username, password, full_name) = PEERS.get(idx).unwrap();
            let peers = total_peers.clone().into_iter().filter(|r| r != username).map(UserIdentifier::Username).collect::<Vec<UserIdentifier>>();
            let username = username.clone();

            let client_kernel = PeerConnectionKernel::new_register_defaults(full_name.as_str(), username.clone().as_str(), password.as_str(), peers, server_addr, |results,remote| async move {
                let success = results.iter().all(|r| r.is_ok());
                log::info!("***PEER {} CONNECT RESULT: {}***", username, success);
                if success {
                    let _ = CLIENT_SUCCESS.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                } else {
                    log::error!("Peer connect failed: {:?}", results);
                    Err(NetworkError::msg(format!("Connect failed: {:?}", results)))
                }
            });

            let client1 = NodeBuilder::default().build(client_kernel).unwrap();
            client_kernels.push(client1);
        }

        let clients = Box::pin(async move {
            client_kernels.try_collect::<()>().await.map(|_| ())
        });

        assert!(futures::future::try_select(server, clients).await.is_ok());
        assert_eq!(CLIENT_SUCCESS.load(Ordering::Relaxed), peer_count);
    }

    #[rstest]
    #[case(2)]
    #[case(3)]
    #[tokio::test]
    async fn peer_to_peer_connect_passwordless(#[case] peer_count: usize) {
        assert!(peer_count > 1);
        crate::test_common::setup_log();
        TestBarrier::setup(peer_count);

        static CLIENT_SUCCESS: AtomicUsize = AtomicUsize::new(0);
        CLIENT_SUCCESS.store(0, Ordering::Relaxed);
        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count).into_iter().map(|_| Uuid::new_v4()).collect::<Vec<Uuid>>();

        for idx in 0..peer_count {
            let uuid = total_peers.get(idx).cloned().unwrap();
            let peers = total_peers.clone().into_iter().filter(|r| r != &uuid).map(UserIdentifier::from).collect::<Vec<UserIdentifier>>();

            let client_kernel = PeerConnectionKernel::new_passwordless_defaults(uuid, server_addr, peers, move |results,remote| async move {
                let success = results.iter().all(|r| r.is_ok());
                log::info!("***PEER {} CONNECT RESULT: {}***", uuid, success);
                if success {
                    let _ = CLIENT_SUCCESS.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                } else {
                    log::error!("Peer connect failed: {:?}", results);
                    Err(NetworkError::msg(format!("Connect failed: {:?}", results)))
                }
            });

            let client1 = NodeBuilder::default().build(client_kernel).unwrap();
            client_kernels.push(client1);
        }

        let clients = Box::pin(async move {
            client_kernels.try_collect::<()>().await.map(|_| ())
        });

        assert!(futures::future::try_select(server, clients).await.is_ok());
        assert_eq!(CLIENT_SUCCESS.load(Ordering::Relaxed), peer_count);
    }
}