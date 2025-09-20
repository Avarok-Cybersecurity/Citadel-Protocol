//! Peer-to-Peer Connection Management
//!
//! This module provides functionality for establishing and managing peer-to-peer connections
//! in the Citadel Protocol. It supports both direct and NAT-traversed connections with
//! configurable security settings and file transfer capabilities.
//!
//! # Features
//! - Multiple simultaneous peer connections
//! - Configurable UDP and security settings per peer
//! - Built-in file transfer support
//! - Automatic peer registration handling
//! - Session password protection
//! - Connection state management
//! - Flexible peer identification
//!
//! # Example
//! ```rust
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::prefabs::client::peer_connection::{PeerConnectionKernel, PeerConnectionSetupAggregator};
//!
//! # fn main() -> Result<(), NetworkError> {
//! async fn connect_to_peers() -> Result<(), NetworkError> {
//!     // Set up connections to multiple peers with different settings
//!     let peers = PeerConnectionSetupAggregator::default()
//!         .with_peer_custom("alice")
//!         .with_udp_mode(UdpMode::Enabled)
//!         .add()
//!         .with_peer_custom("bob")
//!         .with_session_security_settings(Default::default())
//!         .add();
//!
//!     let settings = DefaultServerConnectionSettingsBuilder::transient("127.0.0.1:25021")
//!         .build()?;
//!
//!     let kernel = PeerConnectionKernel::new(
//!         settings,
//!         peers,
//!         |connections, _remote| async move {
//!             println!("Attemping to connect to {} peers!", connections.len());
//!             Ok(())
//!         },
//!     );
//!
//!     Ok(())
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Important Notes
//! - Peers must be mutually registered before connecting
//! - UDP mode affects NAT traversal capabilities
//! - File transfers require proper handler setup
//! - Session passwords must match on both peers
//!
//! # Related Components
//! - [`PeerConnectionSetupAggregator`]: Peer connection configuration
//! - [`FileTransferHandleRx`]: File transfer handling
//! - [`UserIdentifier`]: Peer identification
//! - [`SessionSecuritySettings`]: Connection security
//!
//! [`PeerConnectionSetupAggregator`]: crate::prefabs::client::peer_connection::PeerConnectionSetupAggregator
//! [`FileTransferHandleRx`]: crate::prefabs::client::peer_connection::FileTransferHandleRx
//! [`UserIdentifier`]: crate::prelude::UserIdentifier
//! [`SessionSecuritySettings`]: crate::prelude::SessionSecuritySettings

use crate::prelude::results::PeerConnectSuccess;
use crate::prelude::*;
use crate::test_common::wait_for_peers;
use citadel_io::tokio::sync::mpsc::{Receiver, UnboundedSender};
use citadel_io::{tokio, Mutex};
use citadel_proto::re_imports::async_trait;
use citadel_user::hypernode_account::UserIdentifierExt;
use futures::stream::FuturesUnordered;
use futures::TryStreamExt;
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use uuid::Uuid;

/// After establishing a connection to the central node, this kernel begins connecting to the desired
/// peer(s)
pub struct PeerConnectionKernel<'a, F, Fut, R: Ratchet> {
    inner_kernel: Box<dyn NetKernel<R> + 'a>,
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

#[derive(Debug)]
pub struct FileTransferHandleRx {
    pub inner: citadel_io::tokio::sync::mpsc::UnboundedReceiver<ObjectTransferHandler>,
    pub conn_type: VirtualTargetType,
}

impl FileTransferHandleRx {
    /// Accepts all incoming file transfer handles and processes them in the background
    pub fn accept_all(mut self) {
        let task = tokio::task::spawn(async move {
            let rx = &mut self.inner;
            while let Some(mut handle) = rx.recv().await {
                let task = tokio::task::spawn(async move {
                    if let Err(err) = handle.exhaust_stream().await {
                        let orientation = handle.orientation;
                        log::warn!(target: "citadel", "Error background handling of file transfer for {orientation:?}: {err:?}");
                    }
                });

                drop(task);
            }
        });

        drop(task);
    }
}

impl std::ops::Deref for FileTransferHandleRx {
    type Target = citadel_io::tokio::sync::mpsc::UnboundedReceiver<ObjectTransferHandler>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for FileTransferHandleRx {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Drop for FileTransferHandleRx {
    fn drop(&mut self) {
        log::trace!(target: "citadel", "Dropping file transfer handle receiver {:?}", self.conn_type);
    }
}

#[async_trait]
impl<F, Fut, R: Ratchet> NetKernel<R> for PeerConnectionKernel<'_, F, Fut, R> {
    fn load_remote(&mut self, server_remote: NodeRemote<R>) -> Result<(), NetworkError> {
        self.inner_kernel.load_remote(server_remote)
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        self.inner_kernel.on_start().await
    }

    #[allow(clippy::collapsible_else_if)]
    async fn on_node_event_received(&self, message: NodeResult<R>) -> Result<(), NetworkError> {
        match message {
            NodeResult::ObjectTransferHandle(ObjectTransferHandle {
                ticket: _,
                handle,
                session_cid,
            }) => {
                let is_revfs = matches!(
                    handle.metadata.transfer_type,
                    TransferType::RemoteEncryptedVirtualFilesystem { .. }
                );
                let active_peers = self.shared.active_peer_conns.lock();
                let v_conn = if is_revfs {
                    let peer_cid = if session_cid != handle.source {
                        handle.source
                    } else {
                        handle.receiver
                    };
                    PeerConnectionType::LocalGroupPeer {
                        session_cid,
                        peer_cid,
                    }
                } else {
                    if matches!(
                        handle.orientation,
                        ObjectTransferOrientation::Receiver { .. }
                    ) {
                        PeerConnectionType::LocalGroupPeer {
                            session_cid,
                            peer_cid: handle.source,
                        }
                    } else {
                        PeerConnectionType::LocalGroupPeer {
                            session_cid,
                            peer_cid: handle.receiver,
                        }
                    }
                };

                if let Some(peer_ctx) = active_peers.get(&v_conn) {
                    if let Err(err) = peer_ctx.send_file_transfer_tx.send(handle) {
                        log::warn!(target: "citadel", "Error forwarding file transfer handle: {:?}", err.to_string());
                    }
                } else {
                    log::warn!(target: "citadel", "Unable to find key for inbound file transfer handle: {:?}\n Active Peers: {:?} \n handle_source = {}, handle_receiver = {}", v_conn, active_peers.keys().cloned().collect::<Vec<_>>(), handle.source, handle.receiver);
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
    peer_session_password: Option<PreSharedKey>,
}

pub struct AddedPeer {
    list: PeerConnectionSetupAggregator,
    id: UserIdentifier,
    session_security_settings: Option<SessionSecuritySettings>,
    ensure_registered: bool,
    udp_mode: Option<UdpMode>,
    peer_session_password: Option<PreSharedKey>,
}

impl AddedPeer {
    /// Adds the peer
    pub fn add(mut self) -> PeerConnectionSetupAggregator {
        let new = PeerConnectionSettings {
            id: self.id,
            session_security_settings: self.session_security_settings.unwrap_or_default(),
            udp_mode: self.udp_mode.unwrap_or_default(),
            ensure_registered: self.ensure_registered,
            peer_session_password: self.peer_session_password,
        };

        self.list.inner.push(new);
        self.list
    }

    /// Sets the [`UdpMode`] for this peer to peer connection
    pub fn with_udp_mode(mut self, udp_mode: UdpMode) -> Self {
        self.udp_mode = Some(udp_mode);
        self
    }

    /// Disables the UDP mode for the client-to-server connection. The default setting is Disabled
    pub fn disable_udp(self) -> Self {
        self.with_udp_mode(UdpMode::Disabled)
    }

    /// Enables the UDP mode for the client-to-server connection. The default setting is Disabled
    pub fn enable_udp(self) -> Self {
        self.with_udp_mode(UdpMode::Enabled)
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

    /// Adds a pre-shared key to the peer session password list. Both connecting nodes
    /// must have matching passwords in order to establish a connection. Default is None.
    pub fn with_session_password<T: Into<PreSharedKey>>(mut self, password: T) -> Self {
        self.peer_session_password = Some(password.into());
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
            peer_session_password: None,
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

impl From<Uuid> for PeerConnectionSetupAggregator {
    fn from(user: Uuid) -> Self {
        let user_identifier: UserIdentifier = user.into();
        user_identifier.into()
    }
}

impl From<String> for PeerConnectionSetupAggregator {
    fn from(this: String) -> Self {
        let user_identifier: UserIdentifier = this.into();
        user_identifier.into()
    }
}

impl From<&str> for PeerConnectionSetupAggregator {
    fn from(this: &str) -> Self {
        let user_identifier: UserIdentifier = this.into();
        user_identifier.into()
    }
}

impl From<u64> for PeerConnectionSetupAggregator {
    fn from(this: u64) -> Self {
        let user_identifier: UserIdentifier = this.into();
        user_identifier.into()
    }
}

#[async_trait]
impl<'a, F, Fut, T: Into<PeerConnectionSetupAggregator> + Send + 'a, R: Ratchet>
    PrefabFunctions<'a, T, R> for PeerConnectionKernel<'a, F, Fut, R>
where
    F: FnOnce(
            Receiver<Result<PeerConnectSuccess<R>, NetworkError>>,
            CitadelClientServerConnection<R>,
        ) -> Fut
        + Send
        + 'a,
    Fut: Future<Output = Result<(), NetworkError>> + Send + 'a,
{
    type UserLevelInputFunction = F;
    type SharedBundle = Shared;

    fn get_shared_bundle(&self) -> Self::SharedBundle {
        self.shared.clone()
    }

    #[allow(clippy::blocks_in_conditions)]
    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err(Debug))
    )]
    async fn on_c2s_channel_received(
        connect_success: CitadelClientServerConnection<R>,
        peers_to_connect: T,
        f: Self::UserLevelInputFunction,
        shared: Shared,
    ) -> Result<(), NetworkError> {
        let shared = &shared;
        let session_cid = connect_success.cid;
        let mut peers_already_registered = vec![];

        wait_for_peers().await;
        let peers_to_connect = peers_to_connect.into().inner;

        for peer in &peers_to_connect {
            // TODO: optimize this into a single concurrent operation
            peers_already_registered.push(
                peer.id
                    .search_peer(session_cid, connect_success.account_manager())
                    .await?,
            )
        }

        let remote = connect_success.clone();
        let (ref tx, rx) = citadel_io::tokio::sync::mpsc::channel(peers_to_connect.len());
        let requests = FuturesUnordered::new();

        for (mutually_registered, peer_to_connect) in
            peers_already_registered.into_iter().zip(peers_to_connect)
        {
            // Each task will be responsible for possibly registering to and connecting
            // with the desired peer
            let remote = remote.clone();
            let PeerConnectionSettings {
                id,
                session_security_settings,
                udp_mode,
                ensure_registered,
                peer_session_password,
            } = peer_to_connect;

            let task = async move {
                let inner_task = async move {
                    let (file_transfer_tx, file_transfer_rx) =
                        citadel_io::tokio::sync::mpsc::unbounded_channel();

                    // Get the actual peer CID from the mutual registration info if available
                    let peer_cid = if let Some(mutual_peer) = &mutually_registered {
                        mutual_peer.cid
                    } else {
                        id.get_cid()
                    };

                    let handle = if let Some(_already_registered) = mutually_registered {
                        remote.find_target(session_cid, id).await?
                    } else {
                        // TODO: optimize peer registration + connection in one go
                        log::info!(target: "citadel", "{session_cid} proposing target {id:?} to central node");
                        let handle = remote.propose_target(session_cid, id.clone()).await?;
                        // if the peer is not yet registered to the central node, wait for it to become registered
                        // this is useful especially for testing purposes
                        if ensure_registered {
                            loop {
                                if handle.is_peer_registered().await? {
                                    break;
                                }
                                citadel_io::tokio::time::sleep(std::time::Duration::from_millis(
                                    200,
                                ))
                                .await;
                            }
                        }

                        log::info!(target: "citadel", "{session_cid} registering to peer {id:?}");
                        let _reg_success = handle.register_to_peer().await?;
                        log::info!(target: "citadel", "{session_cid} registered to peer {id:?} registered || success -> now connecting");
                        handle
                    };

                    // Register the peer connection early before attempting to connect
                    // This prevents race conditions where file transfers arrive before connection completes
                    let peer_conn = PeerConnectionType::LocalGroupPeer {
                        session_cid,
                        peer_cid,
                    };
                    let peer_context = PeerContext {
                        conn_type: peer_conn,
                        send_file_transfer_tx: file_transfer_tx.clone(),
                    };
                    log::debug!(target: "citadel", "Early registering peer connection: {peer_conn:?}");
                    let _ = shared
                        .active_peer_conns
                        .lock()
                        .insert(peer_conn, peer_context);

                    handle
                        .connect_to_peer_custom(
                            session_security_settings,
                            udp_mode,
                            peer_session_password,
                        )
                        .await
                        .map(|mut success| {
                            let actual_peer_conn = success.channel.get_peer_conn_type().unwrap();

                            // If the actual peer connection type differs from our early registration,
                            // update it
                            if actual_peer_conn != peer_conn {
                                log::debug!(target: "citadel", "Updating peer connection registration from {peer_conn:?} to {actual_peer_conn:?}");
                                let mut active_peers = shared.active_peer_conns.lock();
                                if let Some(peer_ctx) = active_peers.remove(&peer_conn) {
                                    let _ = active_peers.insert(actual_peer_conn, peer_ctx);
                                }
                            }
                            // Update the existing entry with the file transfer receiver
                            success.incoming_object_transfer_handles = Some(FileTransferHandleRx {
                                inner: file_transfer_rx,
                                conn_type: actual_peer_conn.as_virtual_connection(),
                            });
                            success
                        })
                        .inspect_err(|_err| {
                            // Clean up the early registration on connection failure
                            let _ = shared.active_peer_conns.lock().remove(&peer_conn);
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

        citadel_io::tokio::try_join!(collection_task, f(rx, connect_success)).map(|_| ())
    }

    fn construct(kernel: Box<dyn NetKernel<R> + 'a>) -> Self {
        Self {
            inner_kernel: kernel,
            shared: Shared {
                active_peer_conns: Arc::new(Mutex::new(Default::default())),
            },
            _pd: Default::default(),
        }
    }
}

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::prefabs::client::peer_connection::PeerConnectionKernel;
    use crate::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use crate::prelude::*;
    use crate::remote_ext::results::PeerConnectSuccess;
    use crate::test_common::{server_info, wait_for_peers, TestBarrier};
    use citadel_io::tokio;
    use citadel_io::tokio::sync::mpsc::{Receiver, UnboundedSender};
    use citadel_user::prelude::UserIdentifierExt;
    use futures::stream::FuturesUnordered;
    use futures::TryStreamExt;
    use rstest::rstest;
    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    use uuid::Uuid;

    lazy_static::lazy_static! {
        pub static ref PEERS: Vec<(String, String, String)> = {
            ["alpha", "beta", "charlie", "echo", "delta", "epsilon", "foxtrot"]
            .iter().map(|base| (format!("{base}.username"), format!("{base}.password"), format!("{base}.full_name")))
            .collect()
        };
    }

    #[rstest]
    #[case(2, UdpMode::Enabled)]
    #[case(3, UdpMode::Disabled)]
    #[timeout(Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn peer_to_peer_connect(#[case] peer_count: usize, #[case] udp_mode: UdpMode) {
        assert!(peer_count > 1);
        citadel_logging::setup_log();
        TestBarrier::setup(peer_count);

        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info::<StackedRatchet>();

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
                    .ensure_registered()
                    .with_udp_mode(udp_mode)
                    .with_session_security_settings(SessionSecuritySettings::default())
                    .add();
            }

            let server_connection_settings =
                DefaultServerConnectionSettingsBuilder::credentialed_registration(
                    server_addr,
                    username,
                    full_name,
                    password.as_str(),
                )
                .build()
                .unwrap();

            let username = username.clone();

            let client_kernel = PeerConnectionKernel::new(
                server_connection_settings,
                agg.clone(),
                move |results, connection| async move {
                    log::info!(target: "citadel", "***PEER {username} CONNECTED ***");
                    let session_cid = connection.conn_type.get_session_cid();
                    let check = move |conn: PeerConnectSuccess<_>| async move {
                        let session_cid = conn.channel.get_session_cid();
                        let _mutual_peers = conn
                            .remote
                            .remote()
                            .get_local_group_mutual_peers(session_cid)
                            .await
                            .unwrap();
                        conn
                    };
                    let p2p_remotes = handle_peer_connect_successes(
                        results,
                        session_cid,
                        peer_count,
                        udp_mode,
                        check,
                    )
                    .await
                    .into_iter()
                    .map(|r| (r.channel.get_peer_cid(), r.remote))
                    .collect::<HashMap<_, _>>();

                    // By now, all the network peers have been registered to.
                    // Test that getting the peers (not necessarily mutual)
                    // show up
                    let network_peers = connection.get_peers(None).await.unwrap();
                    for user in agg.inner {
                        let peer_cid = user.id.get_cid();
                        assert!(network_peers.iter().any(|r| r.cid == peer_cid))
                    }

                    // test to make sure the mutuals are valid
                    let session_cid = connection.conn_type.get_session_cid();
                    let mutual_peers = connection
                        .get_local_group_mutual_peers(session_cid)
                        .await
                        .unwrap();
                    for (peer_cid, _) in p2p_remotes {
                        assert!(mutual_peers.iter().any(|r| r.cid == peer_cid))
                    }

                    log::info!(target: "citadel", "***PEER {username} finished all checks***");
                    let _ = client_success.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    connection.shutdown_kernel().await
                },
            );

            let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
            client_kernels.push(async move { client.await.map(|_| ()) });
        }

        let clients = Box::pin(async move { client_kernels.try_collect::<()>().await.map(|_| ()) });

        assert!(futures::future::try_select(server, clients).await.is_ok());

        assert_eq!(client_success.load(Ordering::Relaxed), peer_count);
    }

    #[rstest]
    #[case(2, HeaderObfuscatorSettings::default())]
    #[case(2, HeaderObfuscatorSettings::Enabled)]
    #[case(2, HeaderObfuscatorSettings::EnabledWithKey(12345))]
    #[case(3, HeaderObfuscatorSettings::default())]
    #[timeout(Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn peer_to_peer_connect_transient(
        #[case] peer_count: usize,
        #[case] header_obfuscator_settings: HeaderObfuscatorSettings,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(peer_count > 1);
        citadel_logging::setup_log();
        TestBarrier::setup(peer_count);
        let udp_mode = UdpMode::Enabled;

        let do_deregister = peer_count == 2;

        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info::<StackedRatchet>();

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

            let mut agg = PeerConnectionSetupAggregator::default();

            for peer in peers {
                let security_settings = SessionSecuritySettings {
                    header_obfuscator_settings,
                    ..Default::default()
                };
                agg = agg
                    .with_peer_custom(peer)
                    .with_udp_mode(udp_mode)
                    .ensure_registered()
                    .with_session_security_settings(security_settings)
                    .add();
            }

            let server_connection_settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                    .build()
                    .unwrap();

            let client_kernel = PeerConnectionKernel::new(
                server_connection_settings,
                agg,
                move |results, remote| async move {
                    log::info!(target: "citadel", "***PEER {uuid} CONNECTED***");
                    let session_cid = remote.conn_type.get_session_cid();

                    let check = move |conn: PeerConnectSuccess<_>| async move {
                        if do_deregister {
                            conn.remote
                                .deregister()
                                .await
                                .expect("Deregistration failed");
                            assert!(!conn
                                .remote
                                .inner
                                .account_manager()
                                .get_persistence_handler()
                                .hyperlan_peer_exists(session_cid, conn.channel.get_peer_cid())
                                .await
                                .unwrap());
                        }
                        conn
                    };

                    let _ = handle_peer_connect_successes(
                        results,
                        session_cid,
                        peer_count,
                        udp_mode,
                        check,
                    )
                    .await;

                    log::info!(target: "citadel", "***PEER {uuid} finished all checks***");
                    let _ = client_success.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            );

            let client = DefaultNodeBuilder::default().build(client_kernel)?;
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
    #[case(3)]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_peer_to_peer_file_transfer(
        #[case] peer_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(peer_count > 1);
        citadel_logging::setup_log();
        TestBarrier::setup(peer_count);
        let udp_mode = UdpMode::Enabled;

        let sender_success = &AtomicBool::new(false);
        let receiver_success = &AtomicBool::new(false);

        let (server, server_addr) = server_info::<StackedRatchet>();

        let client_kernels = FuturesUnordered::new();
        let total_peers = (0..peer_count)
            .map(|_| Uuid::new_v4())
            .collect::<Vec<Uuid>>();

        let sender_uuid = total_peers[0];

        for idx in 0..peer_count {
            let uuid = total_peers.get(idx).cloned().unwrap();
            let mut peers = total_peers
                .clone()
                .into_iter()
                .filter(|r| r != &uuid)
                .map(UserIdentifier::from)
                .collect::<Vec<UserIdentifier>>();
            // 0: [1, 2] <-- At idx 0, we want the sender to connect to all other peers
            // 1: [0] <-- At idx 1, we want the receiver to connect to the sender
            // 2: [0] <-- At idx 2, we want the receiver to connect to the sender
            // ..
            // n: [0] <-- At idx n, we want the receiver to connect to the sender
            if idx != 0 {
                peers = vec![sender_uuid.into()];
            }

            let mut agg = PeerConnectionSetupAggregator::default();

            for peer in peers {
                agg = agg
                    .with_peer_custom(peer)
                    .ensure_registered()
                    .with_udp_mode(udp_mode)
                    .with_session_security_settings(SessionSecuritySettings::default())
                    .add();
            }

            let server_connection_settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                    .build()
                    .unwrap();

            let client_kernel = PeerConnectionKernel::new(
                server_connection_settings,
                agg,
                move |results, remote| async move {
                    log::info!(target: "citadel", "***PEER {uuid} CONNECTED***");
                    wait_for_peers().await;
                    let session_cid = remote.conn_type.get_session_cid();
                    let is_sender = idx == 0; // the first peer is the sender, the rest are receivers
                    let check = move |mut conn: PeerConnectSuccess<_>| async move {
                        if is_sender {
                            conn.remote
                                .send_file_with_custom_opts(
                                    "../resources/TheBridge.pdf",
                                    32 * 1024,
                                    TransferType::FileTransfer,
                                )
                                .await
                                .expect("Failed to send file");
                        } else {
                            // TODO: route file-transfer + other events to peer channel
                            let mut handle = conn
                                .incoming_object_transfer_handles
                                .take()
                                .unwrap()
                                .recv()
                                .await
                                .unwrap();
                            handle.accept().unwrap();

                            use citadel_types::proto::ObjectTransferStatus;
                            use futures::StreamExt;
                            let mut path = None;
                            while let Some(status) = handle.next().await {
                                match status {
                                    ObjectTransferStatus::ReceptionComplete => {
                                        let cmp =
                                            include_bytes!("../../../../resources/TheBridge.pdf");
                                        let streamed_data =
                                            citadel_io::tokio::fs::read(path.clone().unwrap())
                                                .await
                                                .unwrap();
                                        assert_eq!(
                                            cmp,
                                            streamed_data.as_slice(),
                                            "Original data and streamed data does not match"
                                        );

                                        log::info!(target: "citadel", "Peer has finished receiving and verifying the file!");
                                        break;
                                    }

                                    ObjectTransferStatus::ReceptionBeginning(file_path, vfm) => {
                                        path = Some(file_path);
                                        assert_eq!(vfm.name, "TheBridge.pdf")
                                    }

                                    _ => {}
                                }
                            }
                        }

                        conn
                    };
                    // Use a peer count of two since we only have one sender and one receiver per pair
                    // However, we need a way of ensuring we collect three results
                    let peer_count = if idx == 0 { peer_count } else { 2 };
                    let _ = handle_peer_connect_successes(
                        results,
                        session_cid,
                        peer_count,
                        udp_mode,
                        check,
                    )
                    .await;

                    if is_sender {
                        sender_success.store(true, Ordering::Relaxed);
                    } else {
                        receiver_success.store(true, Ordering::Relaxed);
                    }

                    log::info!(target: "citadel", "***PEER {uuid} (is_sender: {is_sender}) finished all checks***");
                    wait_for_peers().await;
                    log::info!(target: "citadel", "***PEER {uuid} (is_sender: {is_sender}) shutting down***");
                    remote.shutdown_kernel().await
                },
            );

            let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
            client_kernels.push(async move { client.await.map(|_| ()) });
        }

        let clients = Box::pin(async move { client_kernels.try_collect::<()>().await.map(|_| ()) });

        if let Err(err) = futures::future::try_select(server, clients).await {
            return match err {
                futures::future::Either::Left(res) => Err(res.0.into_string().into()),
                futures::future::Either::Right(res) => Err(res.0.into_string().into()),
            };
        }

        assert!(sender_success.load(Ordering::Relaxed));
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
        let udp_mode = UdpMode::Enabled;

        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info::<StackedRatchet>();

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

            let mut agg = PeerConnectionSetupAggregator::default();

            for peer in peers {
                agg = agg
                    .with_peer_custom(peer)
                    .ensure_registered()
                    .with_udp_mode(udp_mode)
                    .with_session_security_settings(SessionSecuritySettings::default())
                    .add();
            }

            let server_connection_settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                    .build()
                    .unwrap();

            let client_kernel = PeerConnectionKernel::new(
                server_connection_settings,
                agg,
                move |results, remote| async move {
                    log::info!(target: "citadel", "***PEER {uuid} CONNECTED***");
                    let session_cid = remote.conn_type.get_session_cid();

                    let check = move |conn: PeerConnectSuccess<_>| async move {
                        if idx == 0 {
                            for x in 1..10 {
                                assert_eq!(
                                    conn.remote.rekey().await.expect("Failed to rekey"),
                                    Some(x)
                                );
                            }
                        }

                        conn
                    };

                    let results = handle_peer_connect_successes(
                        results,
                        session_cid,
                        peer_count,
                        udp_mode,
                        check,
                    )
                    .await;

                    log::info!(target: "citadel", "***PEER {uuid} finished all check (count: {})s***", results.len());
                    let _ = client_success.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            );

            let client = DefaultNodeBuilder::default().build(client_kernel)?;
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
        let udp_mode = UdpMode::Enabled;

        let client_success = &AtomicUsize::new(0);
        let (server, server_addr) = server_info::<StackedRatchet>();

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

            let mut agg = PeerConnectionSetupAggregator::default();

            for peer in peers {
                agg = agg
                    .with_peer_custom(peer)
                    .ensure_registered()
                    .with_udp_mode(udp_mode)
                    .with_session_security_settings(SessionSecuritySettings::default())
                    .add();
            }

            let server_connection_settings =
                DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                    .build()
                    .unwrap();

            let client_kernel = PeerConnectionKernel::new(
                server_connection_settings,
                agg,
                move |results, remote| async move {
                    log::info!(target: "citadel", "***PEER {uuid} CONNECTED***");
                    wait_for_peers().await;
                    let session_cid = remote.conn_type.get_session_cid();

                    let check = move |conn: PeerConnectSuccess<_>| async move {
                        conn.remote
                            .disconnect()
                            .await
                            .expect("Failed to p2p disconnect");
                        conn
                    };
                    let _ = handle_peer_connect_successes(
                        results,
                        session_cid,
                        peer_count,
                        udp_mode,
                        check,
                    )
                    .await;
                    log::info!(target: "citadel", "***PEER {uuid} finished all checks***");

                    let _ = client_success.fetch_add(1, Ordering::Relaxed);
                    wait_for_peers().await;
                    remote.shutdown_kernel().await
                },
            );

            let client = DefaultNodeBuilder::default().build(client_kernel)?;
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
    #[case(SecrecyMode::BestEffort, Some("test-p2p-password"))]
    #[timeout(std::time::Duration::from_secs(240))]
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn test_p2p_wrong_session_password(
        #[case] secrecy_mode: SecrecyMode,
        #[case] p2p_password: Option<&'static str>,
        #[values(KemAlgorithm::Kyber)] kem: KemAlgorithm,
        #[values(EncryptionAlgorithm::AES_GCM_256)] enx: EncryptionAlgorithm,
    ) {
        citadel_logging::setup_log_no_panic_hook();
        TestBarrier::setup(2);
        let (server, server_addr) = server_info::<StackedRatchet>();
        let peer_0_error_received = &AtomicBool::new(false);
        let peer_1_error_received = &AtomicBool::new(false);

        let uuid0 = Uuid::new_v4();
        let uuid1 = Uuid::new_v4();
        let session_security = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(secrecy_mode)
            .with_crypto_params(kem + enx)
            .build()
            .unwrap();

        let mut peer0_agg = PeerConnectionSetupAggregator::default()
            .with_peer_custom(uuid1)
            .ensure_registered()
            .with_session_security_settings(session_security);

        if let Some(password) = p2p_password {
            peer0_agg = peer0_agg.with_session_password(password);
        }

        let peer0_connection = peer0_agg.add();

        let mut peer1_agg = PeerConnectionSetupAggregator::default()
            .with_peer_custom(uuid0)
            .ensure_registered()
            .with_session_security_settings(session_security);

        if let Some(_password) = p2p_password {
            peer1_agg = peer1_agg.with_session_password("wrong password");
        }

        let peer1_connection = peer1_agg.add();

        let server_connection_settings0 =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid0)
                .with_udp_mode(UdpMode::Enabled)
                .with_session_security_settings(session_security)
                .build()
                .unwrap();

        let server_connection_settings1 =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid1)
                .with_udp_mode(UdpMode::Enabled)
                .with_session_security_settings(session_security)
                .build()
                .unwrap();

        let client_kernel0 = PeerConnectionKernel::new(
            server_connection_settings0,
            peer0_connection,
            move |mut connection, remote| async move {
                wait_for_peers().await;
                let conn = connection.recv().await.unwrap();
                log::trace!(target: "citadel", "Peer 0 {} received: {:?}", remote.conn_type.get_session_cid(), conn);
                if conn.is_ok() {
                    peer_0_error_received.store(true, Ordering::SeqCst);
                }
                wait_for_peers().await;
                remote.shutdown_kernel().await
            },
        );

        let client_kernel1 = PeerConnectionKernel::new(
            server_connection_settings1,
            peer1_connection,
            move |mut connection, remote| async move {
                wait_for_peers().await;
                let conn = connection.recv().await.unwrap();
                log::trace!(target: "citadel", "Peer 1 {} received: {:?}", remote.conn_type.get_session_cid(), conn);
                if conn.is_ok() {
                    peer_1_error_received.store(true, Ordering::SeqCst);
                }
                wait_for_peers().await;
                remote.shutdown_kernel().await
            },
        );

        let client0 = DefaultNodeBuilder::default().build(client_kernel0).unwrap();
        let client1 = DefaultNodeBuilder::default().build(client_kernel1).unwrap();
        let clients = futures::future::try_join(client0, client1);

        let task = async move {
            tokio::select! {
                server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
                client_res = clients => client_res.map(|_| ())
            }
        };

        tokio::time::timeout(Duration::from_secs(120), task)
            .await
            .unwrap()
            .unwrap();

        assert!(!peer_0_error_received.load(Ordering::SeqCst));
        assert!(!peer_1_error_received.load(Ordering::SeqCst));
    }

    async fn handle_peer_connect_successes<F, Fut, R: Ratchet>(
        mut conn_rx: Receiver<Result<PeerConnectSuccess<R>, NetworkError>>,
        session_cid: u64,
        peer_count: usize,
        udp_mode: UdpMode,
        checks: F,
    ) -> Vec<PeerConnectSuccess<R>>
    where
        F: Fn(PeerConnectSuccess<R>) -> Fut + Send + Clone + 'static,
        Fut: Future<Output = PeerConnectSuccess<R>> + Send,
    {
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();

        let task = async move {
            let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut conns = vec![];
            while let Some(conn) = conn_rx.recv().await {
                conns.push(conn);
                if conns.len() == peer_count - 1 {
                    break;
                }
            }

            log::info!(target: "citadel", "~~~*** Peer {session_cid} has {} connections to other peers ***~~~", conns.len());

            for conn in conns {
                let conn = conn.expect("Error receiving peer connection");
                handle_peer_connect_success(
                    conn,
                    done_tx.clone(),
                    session_cid,
                    udp_mode,
                    checks.clone(),
                );
            }

            // Now, wait for all to finish
            let mut ret = vec![];
            while let Some(done) = done_rx.recv().await {
                ret.push(done);
                if ret.len() == peer_count - 1 {
                    break;
                }
            }

            finished_tx
                .send(ret)
                .expect("Error sending finished signal in handle_peer_connect_successes");
        };

        drop(tokio::task::spawn(task));
        let ret = finished_rx
            .await
            .expect("Error receiving finished signal in handle_peer_connect_successes");

        assert_eq!(ret.len(), peer_count - 1);
        ret
    }

    fn handle_peer_connect_success<F, Fut, R: Ratchet>(
        mut conn: PeerConnectSuccess<R>,
        done_tx: UnboundedSender<PeerConnectSuccess<R>>,
        session_cid: u64,
        udp_mode: UdpMode,
        checks: F,
    ) where
        F: Fn(PeerConnectSuccess<R>) -> Fut + Send + Clone + 'static,
        Fut: Future<Output = PeerConnectSuccess<R>> + Send,
    {
        let task = async move {
            let chan = conn.udp_channel_rx.take();
            crate::test_common::p2p_assertions(session_cid, &conn).await;
            crate::test_common::udp_mode_assertions(udp_mode, chan).await;
            let conn = checks(conn).await;
            done_tx
                .send(conn)
                .expect("Error sending done signal in handle_peer_connect_success");
        };

        drop(tokio::task::spawn(task));
    }
}
