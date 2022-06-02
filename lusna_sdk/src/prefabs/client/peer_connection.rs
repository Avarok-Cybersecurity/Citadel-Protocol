use std::marker::PhantomData;
use crate::prelude::{NodeRemote, NetworkError, NetKernel, ConnectSuccess, HdpServerResult, ProtocolRemoteExt, UserIdentifier, ProtocolRemoteTargetExt};
use crate::prelude::results::PeerConnectSuccess;
use futures::{Future, TryStreamExt};
use crate::prefabs::ClientServerRemote;
use hyxe_net::re_imports::async_trait;
use futures::stream::FuturesUnordered;
use tokio::sync::mpsc::Receiver;
use crate::prefabs::client::PrefabFunctions;
use crate::test_common::wait_for_peers;

/// A kernel that connects with the given credentials. If the credentials are not yet registered, then the [`Self::new_register`] function may be used, which will register the account before connecting.
/// This kernel will only allow outbound communication for the provided account
///
/// After establishing a connection to the central node, this kernel then begins connecting to the desired
/// peer(s)
pub struct PeerConnectionKernel<'a, F, Fut> {
    inner_kernel: Box<dyn NetKernel + 'a>,
    // by using fn() -> Fut, the future does not need to be Sync
    _pd: PhantomData<fn() -> (F, Fut)>
}

#[async_trait]
impl<F, Fut> NetKernel for PeerConnectionKernel<'_, F, Fut> {
    fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
        self.inner_kernel.load_remote(server_remote)
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        self.inner_kernel.on_start().await
    }

    async fn on_node_event_received(&self, message: HdpServerResult) -> Result<(), NetworkError> {
        self.inner_kernel.on_node_event_received(message).await
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        self.inner_kernel.on_stop().await
    }
}

/// Allows easy aggregation of [`UserIdentifier`]'s
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


#[async_trait]
impl<'a, F, Fut> PrefabFunctions<'a, Vec<UserIdentifier>> for PeerConnectionKernel<'a, F, Fut>
    where
        F: FnOnce(Receiver<Result<PeerConnectSuccess, NetworkError>>, ClientServerRemote) -> Fut + Send + 'a,
        Fut: Future<Output=Result<(), NetworkError>> + Send + 'a {
    type UserLevelInputFunction = F;
    type SharedBundle = ();

    fn get_shared_bundle(&mut self) -> Self::SharedBundle {
        ()
    }

    async fn on_c2s_channel_received(connect_success: ConnectSuccess, cls_remote: ClientServerRemote, peers_to_connect: Vec<UserIdentifier>, f: Self::UserLevelInputFunction, _: ()) -> Result<(), NetworkError> {
        let implicated_cid = connect_success.cid;
        let mut peers_already_registered = vec![];

        wait_for_peers().await;

        for peer in &peers_to_connect {
            // TODO: optimize this into a single operation
            peers_already_registered.push(peer.search_peer(implicated_cid, cls_remote.inner.account_manager()).await?)
        }

        let remote = cls_remote.inner.clone();
        let (ref tx, rx) = tokio::sync::mpsc::channel(peers_to_connect.len());
        let requests = FuturesUnordered::new();

        for (mutually_registered, peer_to_connect) in peers_already_registered.into_iter().zip(peers_to_connect) {
            // each task will be responsible for possibly registering to and connecting
            // with the desired peer
            let mut remote = remote.clone();
            let task = async move {
                let inner_task = async move {
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

                tx.send(inner_task.await).await.map_err(|err| NetworkError::Generic(err.to_string()))
            };

            requests.push(Box::pin(task))
        }

        let collection_task = async move {
            requests.try_collect::<()>().await
        };

        tokio::try_join!(collection_task, (f)(rx, cls_remote))
            .map(|_| ())
    }

    fn construct(kernel: Box<dyn NetKernel + 'a>) -> Self {
        Self {
            inner_kernel: kernel,
            _pd: Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::sync::atomic::{Ordering, AtomicUsize};
    use crate::test_common::{PEERS, server_info, TestBarrier, wait_for_peers};
    use rstest::rstest;
    use crate::prefabs::client::peer_connection::PeerConnectionKernel;
    use futures::stream::FuturesUnordered;
    use futures::TryStreamExt;
    use uuid::Uuid;

    #[rstest]
    #[case(2)]
    #[case(3)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test]
    async fn peer_to_peer_connect(#[case] peer_count: usize) {
        assert!(peer_count > 1);
        crate::test_common::setup_log();
        TestBarrier::setup(peer_count);

        let ref client_success = AtomicUsize::new(0);
        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count).into_iter().map(|idx| PEERS.get(idx).unwrap().0.clone()).collect::<Vec<String>>();
        
        for idx in 0..peer_count {
            let (username, password, full_name) = PEERS.get(idx).unwrap();
            let peers = total_peers.clone().into_iter().filter(|r| r != username).map(UserIdentifier::Username).collect::<Vec<UserIdentifier>>();
            let username = username.clone();

            let client_kernel = PeerConnectionKernel::new_register_defaults(full_name.as_str(), username.clone().as_str(), password.as_str(), peers, server_addr, move |mut results,remote| async move {
                let mut success = 0;

                while let Some(conn) = results.recv().await {
                    log::info!("User {} received {:?}", username, conn);
                    let _conn = conn?;
                    success += 1;
                    if success == peer_count-1 {
                        break
                    }
                }

                log::info!("***PEER {} CONNECT RESULT: {}***", username, success);
                let _ = client_success.fetch_add(1, Ordering::Relaxed);
                wait_for_peers().await;
                remote.shutdown_kernel().await
            });

            let client = NodeBuilder::default().build(client_kernel).unwrap();
            client_kernels.push(async move {
                client.await.map(|_| ())
            });
        }

        let clients = Box::pin(async move {
            client_kernels.try_collect::<()>().await.map(|_| ())
        });

        assert!(futures::future::try_select(server, clients).await.is_ok());
        assert_eq!(client_success.load(Ordering::Relaxed), peer_count);
    }

    #[rstest]
    #[case(2)]
    #[case(3)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test]
    async fn peer_to_peer_connect_passwordless(#[case] peer_count: usize) {
        assert!(peer_count > 1);
        crate::test_common::setup_log();
        TestBarrier::setup(peer_count);

        let ref client_success = AtomicUsize::new(0);
        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count).into_iter().map(|_| Uuid::new_v4()).collect::<Vec<Uuid>>();

        for idx in 0..peer_count {
            let uuid = total_peers.get(idx).cloned().unwrap();
            let peers = total_peers.clone().into_iter().filter(|r| r != &uuid).map(UserIdentifier::from).collect::<Vec<UserIdentifier>>();

            let client_kernel = PeerConnectionKernel::new_passwordless_defaults(uuid, server_addr, peers, move |mut results,remote| async move {
                let mut success = 0;

                while let Some(conn) = results.recv().await {
                    log::info!("User {} received {:?}", uuid, conn);
                    let _conn = conn?;
                    success += 1;
                    if success == peer_count-1 {
                        break
                    }
                }

                log::info!("***PEER {} CONNECT RESULT: {}***", uuid, success);
                let _ = client_success.fetch_add(1, Ordering::Relaxed);
                wait_for_peers().await;
                remote.shutdown_kernel().await
            });

            let client = NodeBuilder::default().build(client_kernel).unwrap();
            client_kernels.push(async move {
                client.await.map(|_| ())
            });
        }

        let clients = Box::pin(async move {
            client_kernels.try_collect::<()>().await.map(|_| ())
        });

        assert!(futures::future::try_select(server, clients).await.is_ok());
        assert_eq!(client_success.load(Ordering::Relaxed), peer_count);
    }
}