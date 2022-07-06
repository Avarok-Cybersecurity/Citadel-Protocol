use crate::prefabs::client::PrefabFunctions;
use crate::prefabs::ClientServerRemote;
use crate::prelude::results::PeerConnectSuccess;
use crate::prelude::{
    ConnectSuccess, NetKernel, NetworkError, NodeRemote, NodeResult, ProtocolRemoteExt,
    ProtocolRemoteTargetExt, UserIdentifier,
};
use crate::test_common::wait_for_peers;
use futures::stream::FuturesUnordered;
use futures::{Future, TryStreamExt};
use hyxe_net::re_imports::async_trait;
use std::marker::PhantomData;
use tokio::sync::mpsc::Receiver;

/// A kernel that connects with the given credentials. If the credentials are not yet registered, then the [`Self::new_register`] function may be used, which will register the account before connecting.
/// This kernel will only allow outbound communication for the provided account
///
/// After establishing a connection to the central node, this kernel then begins connecting to the desired
/// peer(s)
pub struct PeerConnectionKernel<'a, F, Fut> {
    inner_kernel: Box<dyn NetKernel + 'a>,
    // by using fn() -> Fut, the future does not need to be Sync
    _pd: PhantomData<fn() -> (F, Fut)>,
}

#[async_trait]
impl<F, Fut> NetKernel for PeerConnectionKernel<'_, F, Fut> {
    fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
        self.inner_kernel.load_remote(server_remote)
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        self.inner_kernel.on_start().await
    }

    async fn on_node_event_received(&self, message: NodeResult) -> Result<(), NetworkError> {
        self.inner_kernel.on_node_event_received(message).await
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        self.inner_kernel.on_stop().await
    }
}

/// Allows easy aggregation of [`UserIdentifier`]'s
#[derive(Default)]
pub struct PeerIDAggregator {
    inner: Vec<UserIdentifier>,
}

impl PeerIDAggregator {
    pub fn with_id<T: Into<UserIdentifier>>(mut self, peer: T) -> Self {
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
    F: FnOnce(Receiver<Result<PeerConnectSuccess, NetworkError>>, ClientServerRemote) -> Fut
        + Send
        + 'a,
    Fut: Future<Output = Result<(), NetworkError>> + Send + 'a,
{
    type UserLevelInputFunction = F;
    type SharedBundle = ();

    fn get_shared_bundle(&mut self) -> Self::SharedBundle {
        ()
    }

    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(target = "lusna", skip_all, ret, err(Debug))
    )]
    async fn on_c2s_channel_received(
        connect_success: ConnectSuccess,
        cls_remote: ClientServerRemote,
        peers_to_connect: Vec<UserIdentifier>,
        f: Self::UserLevelInputFunction,
        _: (),
    ) -> Result<(), NetworkError> {
        let implicated_cid = connect_success.cid;
        let mut peers_already_registered = vec![];

        wait_for_peers().await;

        for peer in &peers_to_connect {
            // TODO: optimize this into a single concurrent operation
            peers_already_registered.push(
                peer.search_peer(implicated_cid, cls_remote.inner.account_manager())
                    .await?,
            )
        }

        let remote = cls_remote.inner.clone();
        let (ref tx, rx) = tokio::sync::mpsc::channel(peers_to_connect.len());
        let requests = FuturesUnordered::new();

        for (mutually_registered, peer_to_connect) in
            peers_already_registered.into_iter().zip(peers_to_connect)
        {
            // each task will be responsible for possibly registering to and connecting
            // with the desired peer
            let mut remote = remote.clone();
            let task = async move {
                let inner_task = async move {
                    if let Some(_already_registered) = mutually_registered {
                        let mut handle =
                            remote.find_target(implicated_cid, peer_to_connect).await?;
                        handle.connect_to_peer().await
                    } else {
                        // do both register + connect
                        // TODO: optimize peer registration + connection in one go
                        let mut handle = remote
                            .propose_target(implicated_cid, peer_to_connect.clone())
                            .await?;
                        let _reg_success = handle.register_to_peer().await?;
                        log::trace!(target: "lusna", "Peer {:?} registered || success -> now connecting", peer_to_connect);
                        handle.connect_to_peer().await
                    }
                };

                tx.send(inner_task.await)
                    .await
                    .map_err(|err| NetworkError::Generic(err.to_string()))
            };

            requests.push(Box::pin(task))
        }

        let collection_task = async move { requests.try_collect::<()>().await };

        tokio::try_join!(collection_task, (f)(rx, cls_remote)).map(|_| ())
    }

    fn construct(kernel: Box<dyn NetKernel + 'a>) -> Self {
        Self {
            inner_kernel: kernel,
            _pd: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prefabs::client::peer_connection::PeerConnectionKernel;
    use crate::prelude::*;
    use crate::test_common::{server_info, wait_for_peers, TestBarrier, PEERS};
    use futures::stream::FuturesUnordered;
    use futures::TryStreamExt;
    use rstest::rstest;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    #[rstest]
    #[case(2, false)]
    #[case(3, true)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn peer_to_peer_connect(
        #[case] peer_count: usize,
        #[case] debug_force_nat_timeout: bool,
    ) {
        assert!(peer_count > 1);
        let _ = lusna_logging::setup_log();
        TestBarrier::setup(peer_count);

        if debug_force_nat_timeout {
            std::env::set_var("debug_cause_timeout", "ON");
        }

        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count)
            .into_iter()
            .map(|idx| PEERS.get(idx).unwrap().0.clone())
            .collect::<Vec<String>>();

        for idx in 0..peer_count {
            let (username, password, full_name) = PEERS.get(idx).unwrap();
            let peers = total_peers
                .clone()
                .into_iter()
                .filter(|r| r != username)
                .map(UserIdentifier::Username)
                .collect::<Vec<UserIdentifier>>();
            let username = username.clone();

            let client_kernel = PeerConnectionKernel::new_register_defaults(
                full_name.as_str(),
                username.clone().as_str(),
                password.as_str(),
                peers,
                server_addr,
                move |mut results, remote| async move {
                    let mut success = 0;

                    while let Some(conn) = results.recv().await {
                        log::trace!(target: "lusna", "User {} received {:?}", username, conn);
                        let _conn = conn?;
                        success += 1;
                        if success == peer_count - 1 {
                            break;
                        }
                    }

                    log::trace!(target: "lusna", "***PEER {} CONNECT RESULT: {}***", username, success);
                    let _ = client_success.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            );

            let client = NodeBuilder::default().build(client_kernel).unwrap();
            client_kernels.push(async move { client.await.map(|_| ()) });
        }

        let clients = Box::pin(async move { client_kernels.try_collect::<()>().await.map(|_| ()) });

        assert!(futures::future::try_select(server, clients).await.is_ok());

        if debug_force_nat_timeout {
            std::env::remove_var("debug_cause_timeout");
        }

        assert_eq!(client_success.load(Ordering::Relaxed), peer_count);
    }

    #[rstest]
    #[case(2)]
    #[case(3)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn peer_to_peer_connect_passwordless(
        #[case] peer_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(peer_count > 1);
        let _ = lusna_logging::setup_log();
        TestBarrier::setup(peer_count);

        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count)
            .into_iter()
            .map(|_| Uuid::new_v4())
            .collect::<Vec<Uuid>>();

        for idx in 0..peer_count {
            let uuid = total_peers.get(idx).cloned().unwrap();
            let peers = total_peers
                .clone()
                .into_iter()
                .filter(|r| r != &uuid)
                .map(UserIdentifier::from)
                .collect::<Vec<UserIdentifier>>();

            let client_kernel = PeerConnectionKernel::new_passwordless_defaults(
                uuid,
                server_addr,
                peers,
                move |mut results, remote| async move {
                    let mut success = 0;

                    while let Some(conn) = results.recv().await {
                        log::trace!(target: "lusna", "User {} received {:?}", uuid, conn);
                        let _conn = conn?;
                        success += 1;
                        if success == peer_count - 1 {
                            break;
                        }
                    }

                    log::trace!(target: "lusna", "***PEER {} CONNECT RESULT: {}***", uuid, success);
                    let _ = client_success.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            );

            let client = NodeBuilder::default().build(client_kernel).unwrap();
            client_kernels.push(async move { client.await.map(|_| ()) });
        }

        let clients = Box::pin(async move { client_kernels.try_collect::<()>().await.map(|_| ()) });

        if let Err(err) = futures::future::try_select(server, clients).await {
            return match err {
                futures::future::Either::Left(res) => Err(res.0.into_string().into()),
                futures::future::Either::Right(res) => Err(res.0.into_string().into()),
            };
        }

        assert_eq!(client_success.load(Ordering::Relaxed), peer_count);
        Ok(())
    }
}
