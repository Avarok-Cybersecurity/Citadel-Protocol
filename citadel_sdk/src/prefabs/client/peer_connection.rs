use crate::prefabs::client::PrefabFunctions;
use crate::prefabs::ClientServerRemote;
use crate::prelude::results::PeerConnectSuccess;
use crate::prelude::*;
use crate::test_common::wait_for_peers;
use citadel_io::Mutex;
use citadel_proto::prelude::{PeerConnectionType, SessionSecuritySettings, UdpMode};
use citadel_proto::re_imports::async_trait;
use futures::stream::FuturesUnordered;
use futures::{Future, TryStreamExt};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, UnboundedSender};

/// A kernel that connects with the given credentials. If the credentials are not yet registered, then the [`Self::new_register`] function may be used, which will register the account before connecting.
/// This kernel will only allow outbound communication for the provided account
///
/// After establishing a connection to the central node, this kernel then begins connecting to the desired
/// peer(s)
pub struct PeerConnectionKernel<'a, F, Fut> {
    inner_kernel: Box<dyn NetKernel + 'a>,
    shared: Shared,
    // by using fn() -> Fut, the future does not need to be Sync
    _pd: PhantomData<fn() -> (F, Fut)>,
}

#[derive(Clone)]
#[doc(hidden)]
pub struct Shared {
    active_peer_conns: Arc<Mutex<HashMap<PeerConnectionType, PeerContext>>>,
}

struct PeerContext {
    #[allow(dead_code)]
    conn_type: PeerConnectionType,
    send_file_transfer_tx: UnboundedSender<ObjectTransferHandler>,
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
        match message {
            NodeResult::ObjectTransferHandle(ObjectTransferHandle { ticket: _, handle }) => {
                let v_conn = if matches!(
                    handle.orientation,
                    ObjectTransferOrientation::Receiver { .. }
                ) {
                    PeerConnectionType::LocalGroupPeer {
                        implicated_cid: handle.receiver,
                        peer_cid: handle.source,
                    }
                } else {
                    PeerConnectionType::LocalGroupPeer {
                        implicated_cid: handle.source,
                        peer_cid: handle.receiver,
                    }
                };

                let active_peers = self.shared.active_peer_conns.lock();
                if let Some(peer_ctx) = active_peers.get(&v_conn) {
                    if let Err(err) = peer_ctx.send_file_transfer_tx.send(handle) {
                        log::warn!(target: "citadel", "Error forwarding file transfer handle: {:?}", err);
                    }
                } else {
                    log::warn!(target: "citadel", "Unable to find key for inbound file transfer handle: {:?}", v_conn);
                }

                Ok(())
            }

            NodeResult::Disconnect(Disconnect {
                ticket: _,
                cid_opt: _,
                success: _,
                v_conn_type: Some(v_conn),
                ..
            }) => {
                if let Some(v_conn) = v_conn.try_as_peer_connection() {
                    let mut active_peers = self.shared.active_peer_conns.lock();
                    let _ = active_peers.remove(&v_conn);
                }

                Ok(())
            }

            unprocessed => {
                // pass any unprocessed events to the lower kernel
                self.inner_kernel.on_node_event_received(unprocessed).await
            }
        }
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        self.inner_kernel.on_stop().await
    }
}

/// Allows easy aggregation of [`UserIdentifier`]'s and custom settings for the connection
/// request
#[derive(Debug, Default, Clone)]
pub struct PeerConnectionSetupAggregator {
    inner: Vec<PeerConnectionSettings>,
}

#[derive(Debug, Clone)]
struct PeerConnectionSettings {
    id: UserIdentifier,
    session_security_settings: SessionSecuritySettings,
    udp_mode: UdpMode,
    ensure_registered: bool,
}

pub struct AddedPeer {
    list: PeerConnectionSetupAggregator,
    id: UserIdentifier,
    session_security_settings: Option<SessionSecuritySettings>,
    ensure_registered: bool,
    udp_mode: Option<UdpMode>,
}

impl AddedPeer {
    /// Adds the peer
    pub fn add(mut self) -> PeerConnectionSetupAggregator {
        let new = PeerConnectionSettings {
            id: self.id,
            session_security_settings: self.session_security_settings.unwrap_or_default(),
            udp_mode: self.udp_mode.unwrap_or_default(),
            ensure_registered: self.ensure_registered,
        };

        self.list.inner.push(new);
        self.list
    }

    /// Sets the [`UdpMode`] for this peer to peer connection
    pub fn with_udp_mode(mut self, udp_mode: UdpMode) -> Self {
        self.udp_mode = Some(udp_mode);
        self
    }

    /// Sets the [`SessionSecuritySettings`] for this peer to peer connection
    pub fn with_session_security_settings(
        mut self,
        session_security_settings: SessionSecuritySettings,
    ) -> Self {
        self.session_security_settings = Some(session_security_settings);
        self
    }

    /// Ensures that the target user is registered before attempting to connect
    pub fn ensure_registered(mut self) -> Self {
        self.ensure_registered = true;
        self
    }
}

impl PeerConnectionSetupAggregator {
    /// Adds a peer with default connection settings
    /// ```
    /// use citadel_sdk::prelude::*;
    /// let peers = PeerConnectionSetupAggregator::default()
    ///     .with_peer("john.doe")
    ///     .with_peer("alice")
    ///     .with_peer("bob");
    /// ```
    pub fn with_peer<T: Into<UserIdentifier>>(self, peer: T) -> PeerConnectionSetupAggregator {
        self.with_peer_custom(peer).add()
    }

    /// Adds a peer with custom settings
    /// ```
    /// use citadel_sdk::prelude::*;
    /// // Set up a p2p connection to john.doe with udp enabled,
    /// // and, a p2p connection to alice with udp disabled and
    /// // custom security settings
    /// let peers = PeerConnectionSetupAggregator::default()
    ///     .with_peer_custom("john.doe")
    ///     .with_udp_mode(UdpMode::Enabled)
    ///     .add()
    ///     .with_peer_custom("alice")
    ///     .with_udp_mode(UdpMode::Disabled)
    ///     .with_session_security_settings(Default::default())
    ///     .add();
    /// ```
    pub fn with_peer_custom<T: Into<UserIdentifier>>(self, peer: T) -> AddedPeer {
        AddedPeer {
            list: self,
            id: peer.into(),
            ensure_registered: false,
            session_security_settings: None,
            udp_mode: None,
        }
    }
}

impl From<PeerConnectionSetupAggregator> for Vec<PeerConnectionSettings> {
    fn from(this: PeerConnectionSetupAggregator) -> Self {
        this.inner
    }
}

impl From<Vec<UserIdentifier>> for PeerConnectionSetupAggregator {
    fn from(ids: Vec<UserIdentifier>) -> Self {
        let mut this = PeerConnectionSetupAggregator::default();
        for peer in ids {
            this = this.with_peer(peer);
        }

        this
    }
}

impl From<UserIdentifier> for PeerConnectionSetupAggregator {
    fn from(this: UserIdentifier) -> Self {
        Self::from(vec![this])
    }
}

#[async_trait]
impl<'a, F, Fut, T: Into<PeerConnectionSetupAggregator> + Send + 'a> PrefabFunctions<'a, T>
    for PeerConnectionKernel<'a, F, Fut>
where
    F: FnOnce(Receiver<Result<PeerConnectSuccess, NetworkError>>, ClientServerRemote) -> Fut
        + Send
        + 'a,
    Fut: Future<Output = Result<(), NetworkError>> + Send + 'a,
{
    type UserLevelInputFunction = F;
    type SharedBundle = Shared;

    fn get_shared_bundle(&self) -> Self::SharedBundle {
        self.shared.clone()
    }

    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(target = "citadel", skip_all, ret, err(Debug))
    )]
    async fn on_c2s_channel_received(
        connect_success: ConnectionSuccess,
        cls_remote: ClientServerRemote,
        peers_to_connect: T,
        f: Self::UserLevelInputFunction,
        shared: Shared,
    ) -> Result<(), NetworkError> {
        let shared = &shared;
        let implicated_cid = connect_success.cid;
        let mut peers_already_registered = vec![];

        wait_for_peers().await;
        let peers_to_connect = peers_to_connect.into().inner;

        for peer in &peers_to_connect {
            // TODO: optimize this into a single concurrent operation
            peers_already_registered.push(
                peer.id
                    .search_peer(implicated_cid, cls_remote.inner.account_manager())
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
            let remote = remote.clone();
            let PeerConnectionSettings {
                id,
                session_security_settings,
                udp_mode,
                ensure_registered,
            } = peer_to_connect;

            let task = async move {
                let inner_task = async move {
                    let (file_transfer_tx, file_transfer_rx) =
                        tokio::sync::mpsc::unbounded_channel();

                    let handle = if let Some(_already_registered) = mutually_registered {
                        remote.find_target(implicated_cid, id).await?
                    } else {
                        // TODO: optimize peer registration + connection in one go
                        let handle = remote.propose_target(implicated_cid, id.clone()).await?;

                        // if the peer is not yet registered to the central node, wait for it to become registered
                        // this is useful especially for testing purposes
                        if ensure_registered {
                            loop {
                                if handle.is_peer_registered().await? {
                                    break;
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            }
                        }

                        let _reg_success = handle.register_to_peer().await?;
                        log::trace!(target: "citadel", "Peer {:?} registered || success -> now connecting", id);
                        handle
                    };

                    handle
                        .connect_to_peer_custom(session_security_settings, udp_mode)
                        .await
                        .map(|mut success| {
                            let peer_conn = success.channel.get_peer_conn_type().unwrap();
                            let peer_context = PeerContext {
                                conn_type: success.channel.get_peer_conn_type().unwrap(),
                                send_file_transfer_tx: file_transfer_tx,
                            };
                            // add an incoming file transfer receiver
                            success.incoming_object_transfer_handles = Some(file_transfer_rx);
                            let _ = shared
                                .active_peer_conns
                                .lock()
                                .insert(peer_conn, peer_context);
                            success
                        })
                };

                tx.send(inner_task.await)
                    .await
                    .map_err(|err| NetworkError::Generic(err.to_string()))
            };

            requests.push(Box::pin(task))
        }

        // TODO: What should be done if a peer conn fails? No room for error here
        let collection_task = async move { requests.try_collect::<()>().await };

        tokio::try_join!(collection_task, (f)(rx, cls_remote)).map(|_| ())
    }

    fn construct(kernel: Box<dyn NetKernel + 'a>) -> Self {
        Self {
            inner_kernel: kernel,
            shared: Shared {
                active_peer_conns: Arc::new(Mutex::new(Default::default())),
            },
            _pd: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prefabs::client::peer_connection::{
        PeerConnectionKernel, PeerConnectionSetupAggregator,
    };
    use crate::prelude::*;
    use crate::test_common::{server_info, wait_for_peers, TestBarrier, PEERS};
    use futures::stream::FuturesUnordered;
    use futures::TryStreamExt;
    use rstest::rstest;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
        citadel_logging::setup_log();
        TestBarrier::setup(peer_count);

        let udp_mode = if debug_force_nat_timeout {
            std::env::set_var("debug_cause_timeout", "ON");
            UdpMode::Disabled
        } else {
            UdpMode::Enabled
        };

        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count)
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

            let mut agg = PeerConnectionSetupAggregator::default();

            for peer in peers {
                agg = agg
                    .with_peer_custom(peer)
                    .with_udp_mode(udp_mode)
                    .with_session_security_settings(SessionSecuritySettings::default())
                    .add();
            }

            let username = username.clone();

            let client_kernel = PeerConnectionKernel::new_register_defaults(
                full_name.as_str(),
                username.clone().as_str(),
                password.as_str(),
                agg.clone(),
                server_addr,
                move |mut results, mut remote| async move {
                    let mut success = 0;
                    let mut p2p_remotes = HashMap::new();

                    while let Some(conn) = results.recv().await {
                        log::trace!(target: "citadel", "User {} received {:?}", username, conn);
                        let conn = conn?;
                        crate::test_common::udp_mode_assertions(udp_mode, conn.udp_channel_rx).await;
                        success += 1;
                        let _ = p2p_remotes.insert(conn.channel.get_peer_cid(), conn.remote);
                        if success == peer_count - 1 {
                            break;
                        }
                    }

                    // by now, all the network peers have been registered to
                    // test that getting the peers (not necessarily mutual)
                    // show up
                    let network_peers = remote.get_peers(None).await.unwrap();
                    for user in agg.inner {
                        let peer_cid = user.id.get_cid();
                        assert!(network_peers.iter().any(|r| r.cid == peer_cid))
                    }

                    // test to make sure the mutuals are valid
                    let implicated_cid = remote.conn_type.get_implicated_cid();
                    let mutual_peers = remote
                        .inner
                        .get_local_group_mutual_peers(implicated_cid)
                        .await
                        .unwrap();
                    for (peer_cid, _) in p2p_remotes {
                        assert!(mutual_peers.iter().any(|r| r.cid == peer_cid))
                    }

                    log::trace!(target: "citadel", "***PEER {} CONNECT RESULT: {}***", username, success);
                    let _ = client_success.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            ).unwrap();

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
        citadel_logging::setup_log();
        TestBarrier::setup(peer_count);

        let do_deregister = peer_count == 2;

        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count)
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
                    let implicated_cid = remote.conn_type.get_implicated_cid();

                    while let Some(conn) = results.recv().await {
                        log::trace!(target: "citadel", "User {} received {:?}", uuid, conn);
                        let conn = conn?;
                        let peer_cid = conn.channel.get_peer_cid();

                        crate::test_common::p2p_assertions(implicated_cid, &conn).await;

                        crate::test_common::udp_mode_assertions(
                            Default::default(),
                            conn.udp_channel_rx,
                        )
                        .await;

                        if do_deregister {
                            conn.remote.deregister().await?;
                            assert!(!conn
                                .remote
                                .inner
                                .account_manager()
                                .get_persistence_handler()
                                .hyperlan_peer_exists(implicated_cid, peer_cid)
                                .await
                                .unwrap());
                        }

                        success += 1;
                        if success == peer_count - 1 {
                            break;
                        }
                    }

                    log::trace!(target: "citadel", "***PEER {} CONNECT RESULT: {}***", uuid, success);
                    let _ = client_success.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            ).unwrap();

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

    #[rstest]
    #[case(2)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_peer_to_peer_file_transfer(
        #[case] peer_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(peer_count > 1);
        citadel_logging::setup_log();
        TestBarrier::setup(peer_count);

        let client_success = &AtomicBool::new(false);
        let receiver_success = &AtomicBool::new(false);

        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count)
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
                    let implicated_cid = remote.conn_type.get_implicated_cid();

                    while let Some(conn) = results.recv().await {
                        log::trace!(target: "citadel", "User {} received {:?}", uuid, conn);
                        wait_for_peers().await;
                        let conn = conn?;
                        //let peer_cid = conn.channel.get_peer_cid();

                        crate::test_common::p2p_assertions(implicated_cid, &conn).await;

                        // one user will send the file, the other will receive the file
                        if idx == 0 {
                            conn.remote
                                .send_file_with_custom_opts(
                                    "../resources/TheBridge.pdf",
                                    32 * 1024,
                                    TransferType::FileTransfer
                                )
                                .await?;

                            client_success.store(true, Ordering::Relaxed);
                        } else {
                            // TODO: route file-transfer + other events to peer channel
                            let mut handle = conn
                                .incoming_object_transfer_handles
                                .unwrap()
                                .recv()
                                .await
                                .unwrap();
                            handle.accept().unwrap();

                            use futures::StreamExt;
                            let mut path = None;
                            while let Some(status) = handle.next().await {
                                match status {
                                    ObjectTransferStatus::ReceptionComplete => {
                                        log::trace!(target: "citadel", "Peer has finished receiving the file!");
                                        let cmp =
                                            include_bytes!("../../../../resources/TheBridge.pdf");
                                        let streamed_data =
                                            tokio::fs::read(path.clone().unwrap()).await.unwrap();
                                        assert_eq!(
                                            cmp,
                                            streamed_data.as_slice(),
                                            "Original data and streamed data does not match"
                                        );

                                        break;
                                    }

                                    ObjectTransferStatus::ReceptionBeginning(file_path, vfm) => {
                                        path = Some(file_path);
                                        assert_eq!(vfm.name, "TheBridge.pdf")
                                    }

                                    _ => {}
                                }
                            }

                            receiver_success.store(true, Ordering::Relaxed);
                        }

                        success += 1;
                        if success == peer_count - 1 {
                            break;
                        }
                    }

                    log::trace!(target: "citadel", "***PEER {} CONNECT RESULT: {}***", uuid, success);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            ).unwrap();

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

        assert!(client_success.load(Ordering::Relaxed));
        assert!(receiver_success.load(Ordering::Relaxed));
        Ok(())
    }

    #[rstest]
    #[case(2)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_peer_to_peer_rekey(
        #[case] peer_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(peer_count > 1);
        citadel_logging::setup_log();
        TestBarrier::setup(peer_count);

        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count)
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
                    let implicated_cid = remote.conn_type.get_implicated_cid();

                    while let Some(conn) = results.recv().await {
                        log::trace!(target: "citadel", "User {} received {:?}", uuid, conn);
                        let conn = conn?;
                        crate::test_common::p2p_assertions(implicated_cid, &conn).await;

                        if idx == 0 {
                            for x in 1..10 {
                                assert_eq!(conn.remote.rekey().await?, Some(x));
                            }
                        }

                        success += 1;
                        if success == peer_count - 1 {
                            break;
                        }
                    }

                    log::trace!(target: "citadel", "***PEER {} CONNECT RESULT: {}***", uuid, success);
                    let _ = client_success.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            ).unwrap();

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

    #[rstest]
    #[case(2)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_peer_to_peer_disconnect(
        #[case] peer_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(peer_count > 1);
        citadel_logging::setup_log();
        TestBarrier::setup(peer_count);

        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count)
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
                    let implicated_cid = remote.conn_type.get_implicated_cid();

                    while let Some(conn) = results.recv().await {
                        log::trace!(target: "citadel", "User {} received {:?}", uuid, conn);
                        let conn = conn?;
                        crate::test_common::p2p_assertions(implicated_cid, &conn).await;
                        conn.remote.disconnect().await?;
                        success += 1;
                        if success == peer_count - 1 {
                            break;
                        }
                    }

                    log::trace!(target: "citadel", "***PEER {} CONNECT RESULT: {}***", uuid, success);
                    let _ = client_success.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            ).unwrap();

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
