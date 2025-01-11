//! Remote Protocol Extensions
//!
//! This module extends the core NodeRemote functionality with high-level operations
//! for managing connections, file transfers, and peer interactions in the Citadel
//! Protocol network.
//!
//! # Features
//! - User registration and authentication
//! - Connection management
//! - File transfer operations
//! - Virtual filesystem support
//! - Peer discovery and management
//! - Group communication
//! - Security settings configuration
//!
//! # Example
//! ```rust
//! use citadel_sdk::prelude::*;
//!
//! async fn example<R: Ratchet>(remote: NodeRemote<R>) -> Result<(), NetworkError> {
//!     // Register a new user
//!     let reg = remote.register_with_defaults(
//!         "127.0.0.1:25021",
//!         "John Doe",
//!         "john.doe",
//!         "password123"
//!     ).await?;
//!
//!     // Connect to a peer
//!     let auth = AuthenticationRequest::credentialed("john.doe", "password123");
//!     let conn = remote.connect_with_defaults(auth).await?;
//!
//!     // Send a file to a peer
//!     remote.find_target("john.doe", "peer.name")
//!         .await?
//!         .send_file("/path/to/file.txt")
//!         .await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//! - All operations are asynchronous
//! - Connections are automatically managed
//! - File transfers support chunking
//! - Virtual filesystem is encrypted
//! - Peer connections require mutual registration
//!
//! # Related Components
//! - [`NodeRemote`]: Core remote interface
//! - [`ClientServerRemote`]: Client-server communication
//! - [`PeerRemote`]: Peer-to-peer communication
//! - [`CitadelClientServerConnection`]: Connection management
//! - [`RegisterSuccess`]: Registration handling
//!

use crate::prefabs::ClientServerRemote;
use crate::prelude::results::{PeerConnectSuccess, PeerRegisterStatus};
use crate::prelude::*;
use crate::remote_ext::remote_specialization::PeerRemote;
use crate::remote_ext::results::LocalGroupPeerFullInfo;
use std::ops::{Deref, DerefMut};

use futures::StreamExt;
use std::path::PathBuf;
use std::time::Duration;

pub(crate) mod user_ids {
    use crate::prelude::*;
    use std::ops::Deref;

    #[derive(Debug)]
    /// A reference to a user identifier
    pub struct SymmetricIdentifierHandleRef<'a, R: Ratchet> {
        pub(crate) user: VirtualTargetType,
        pub(crate) remote: &'a NodeRemote<R>,
        pub(crate) target_username: Option<String>,
    }

    impl<R: Ratchet> SymmetricIdentifierHandleRef<'_, R> {
        pub fn into_owned(self) -> SymmetricIdentifierHandle<R> {
            SymmetricIdentifierHandle {
                user: self.user,
                remote: self.remote.clone(),
                target_username: self.target_username,
            }
        }
    }

    #[derive(Clone, Debug)]
    /// A convenience structure for executing commands that depend on a specific registered user
    pub struct SymmetricIdentifierHandle<R: Ratchet> {
        user: VirtualTargetType,
        remote: NodeRemote<R>,
        target_username: Option<String>,
    }

    pub trait TargetLockedRemote<R: Ratchet>: Send + Sync {
        fn user(&self) -> &VirtualTargetType;
        fn remote(&self) -> &NodeRemote<R>;
        fn target_username(&self) -> Option<&str>;
        fn user_mut(&mut self) -> &mut VirtualTargetType;
        fn session_security_settings(&self) -> Option<&SessionSecuritySettings>;
    }

    impl<R: Ratchet> TargetLockedRemote<R> for SymmetricIdentifierHandleRef<'_, R> {
        fn user(&self) -> &VirtualTargetType {
            &self.user
        }
        fn remote(&self) -> &NodeRemote<R> {
            self.remote
        }
        fn target_username(&self) -> Option<&str> {
            self.target_username.as_deref()
        }
        fn user_mut(&mut self) -> &mut VirtualTargetType {
            &mut self.user
        }

        fn session_security_settings(&self) -> Option<&SessionSecuritySettings> {
            None
        }
    }

    impl<R: Ratchet> TargetLockedRemote<R> for SymmetricIdentifierHandle<R> {
        fn user(&self) -> &VirtualTargetType {
            &self.user
        }
        fn remote(&self) -> &NodeRemote<R> {
            &self.remote
        }
        fn target_username(&self) -> Option<&str> {
            self.target_username.as_deref()
        }
        fn user_mut(&mut self) -> &mut VirtualTargetType {
            &mut self.user
        }

        fn session_security_settings(&self) -> Option<&SessionSecuritySettings> {
            None
        }
    }

    impl<R: Ratchet> From<SymmetricIdentifierHandleRef<'_, R>> for SymmetricIdentifierHandle<R> {
        fn from(this: SymmetricIdentifierHandleRef<'_, R>) -> Self {
            this.into_owned()
        }
    }

    impl<R: Ratchet> Deref for SymmetricIdentifierHandle<R> {
        type Target = NodeRemote<R>;

        fn deref(&self) -> &Self::Target {
            &self.remote
        }
    }

    impl<R: Ratchet> Deref for SymmetricIdentifierHandleRef<'_, R> {
        type Target = NodeRemote<R>;

        fn deref(&self) -> &Self::Target {
            self.remote
        }
    }
}

/// Contains the elements required to communicate with the adjacent node
pub struct CitadelClientServerConnection<R: Ratchet> {
    /// An interface to send ordered, reliable, and encrypted messages
    pub(crate) channel: Option<PeerChannel<R>>,
    pub remote: ClientServerRemote<R>,
    /// Only available if UdpMode was enabled at the beginning of a session
    pub udp_channel_rx: Option<citadel_io::tokio::sync::oneshot::Receiver<UdpChannel<R>>>,
    /// Contains the Google auth minted at the central server (if the central server enabled it), as well as any other services enabled by the central server
    pub services: ServicesObject,
    pub cid: u64,
    pub session_security_settings: SessionSecuritySettings,
}

impl<R: Ratchet> CitadelClientServerConnection<R> {
    /// Splits the channel into a send and receive half. This will render
    /// the other fields of this connection object innaccessible
    ///
    /// # Panics
    ///  - If the channel has already been taken
    pub fn split(self) -> (PeerChannelSendHalf<R>, PeerChannelRecvHalf<R>) {
        self.channel.expect("Channel already taken").split()
    }

    pub fn take_channel(&mut self) -> Option<PeerChannel<R>> {
        self.channel.take()
    }
}

impl<R: Ratchet> Deref for CitadelClientServerConnection<R> {
    type Target = ClientServerRemote<R>;

    fn deref(&self) -> &Self::Target {
        &self.remote
    }
}

impl<R: Ratchet> DerefMut for CitadelClientServerConnection<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.remote
    }
}

/// Contains the elements entailed by a successful registration
pub struct RegisterSuccess {
    pub cid: u64,
}

#[async_trait]
/// Endows the [NodeRemote](NodeRemote) with additional functions
pub trait ProtocolRemoteExt<R: Ratchet>: Remote<R> {
    /// Registers with custom settings
    /// Returns a ticket which is used to uniquely identify the request in the protocol
    async fn register<
        T: std::net::ToSocketAddrs + Send,
        P: Into<String> + Send,
        V: Into<String> + Send,
        K: Into<SecBuffer> + Send,
    >(
        &self,
        addr: T,
        full_name: P,
        username: V,
        proposed_password: K,
        default_security_settings: SessionSecuritySettings,
        server_password: Option<PreSharedKey>,
    ) -> Result<RegisterSuccess, NetworkError> {
        let creds =
            ProposedCredentials::new_register(full_name, username, proposed_password.into())
                .await?;
        let register_request = NodeRequest::RegisterToHypernode(RegisterToHypernode {
            remote_addr: addr
                .to_socket_addrs()?
                .next()
                .ok_or(NetworkError::InternalError("Invalid socket addr"))?,
            proposed_credentials: creds,
            static_security_settings: default_security_settings,
            session_password: server_password.unwrap_or_default(),
        });

        let mut subscription = self.send_callback_subscription(register_request).await?;
        while let Some(status) = subscription.next().await {
            match map_errors(status)? {
                NodeResult::RegisterOkay(RegisterOkay { cid, .. }) => {
                    return Ok(RegisterSuccess { cid });
                }
                NodeResult::RegisterFailure(err) => {
                    return Err(NetworkError::Generic(err.error_message));
                }
                NodeResult::Disconnect(err) => {
                    return Err(NetworkError::Generic(err.message));
                }
                evt => {
                    log::warn!(target: "citadel", "Invalid NodeResult for Register request received: {evt:?}");
                }
            }
        }

        Err(NetworkError::InternalError(
            "Internal kernel stream died (register)",
        ))
    }

    /// Registers using the default settings. The default uses No Google FCM keys and the default session security settings
    /// Returns a ticket which is used to uniquely identify the request in the protocol
    async fn register_with_defaults<
        T: std::net::ToSocketAddrs + Send,
        P: Into<String> + Send,
        V: Into<String> + Send,
        K: Into<SecBuffer> + Send,
    >(
        &self,
        addr: T,
        full_name: P,
        username: V,
        proposed_password: K,
    ) -> Result<RegisterSuccess, NetworkError> {
        self.register(
            addr,
            full_name,
            username,
            proposed_password,
            Default::default(),
            Default::default(),
        )
        .await
    }

    /// Connects with custom settings
    /// Returns a ticket which is used to uniquely identify the request in the protocol
    async fn connect(
        &self,
        auth: AuthenticationRequest,
        connect_mode: ConnectMode,
        udp_mode: UdpMode,
        keep_alive_timeout: Option<Duration>,
        session_security_settings: SessionSecuritySettings,
        server_password: Option<PreSharedKey>,
    ) -> Result<CitadelClientServerConnection<R>, NetworkError> {
        let connect_request = NodeRequest::ConnectToHypernode(ConnectToHypernode {
            auth_request: auth,
            connect_mode,
            udp_mode,
            keep_alive_timeout: keep_alive_timeout.map(|r| r.as_secs()),
            session_security_settings,
            session_password: server_password.unwrap_or_default(),
        });

        let mut subscription = self.send_callback_subscription(connect_request).await?;
        let status = subscription
            .next()
            .await
            .ok_or(NetworkError::InternalError(
                "Internal kernel stream died (connect)",
            ))?;

        return match map_errors(status)? {
            NodeResult::ConnectSuccess(ConnectSuccess {
                ticket: _,
                session_cid: cid,
                remote_addr: _,
                is_personal: _,
                v_conn_type,
                services,
                welcome_message: _,
                channel,
                udp_rx_opt: udp_channel_rx,
                session_security_settings,
            }) => Ok(CitadelClientServerConnection {
                remote: ClientServerRemote::new(
                    v_conn_type,
                    self.remote_ref().clone(),
                    session_security_settings,
                    None,
                    None,
                ),
                channel: Some(channel),
                udp_channel_rx,
                services,
                cid,
                session_security_settings,
            }),
            NodeResult::ConnectFail(ConnectFail {
                ticket: _,
                cid_opt: _,
                error_message: err,
            }) => Err(NetworkError::Generic(err)),
            NodeResult::Disconnect(err) => {
                return Err(NetworkError::Generic(err.message));
            }
            res => Err(NetworkError::msg(format!(
                "[connect] An unexpected response occurred: {res:?}"
            ))),
        };
    }

    /// Connects with the default settings
    /// If FCM keys were created during the registration phase, then those keys will be used for the session. If new FCM keys need to be used, consider using [`Self::connect`]
    async fn connect_with_defaults(
        &self,
        auth: AuthenticationRequest,
    ) -> Result<CitadelClientServerConnection<R>, NetworkError> {
        self.connect(
            auth,
            Default::default(),
            Default::default(),
            None,
            Default::default(),
            Default::default(),
        )
        .await
    }

    /// Creates a valid target identifier used to make protocol requests. Raw user IDs or usernames can be used
    /// ```
    /// use citadel_sdk::prelude::*;
    /// # use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    ///
    /// let server_connection_settings = DefaultServerConnectionSettingsBuilder::credentialed_login("127.0.0.1:25021", "john.doe", "password").build().unwrap();
    ///
    /// # SingleClientServerConnectionKernel::new(server_connection_settings, |conn| async move {
    /// conn.find_target("my_account", "my_peer").await?.send_file("/path/to/file.pdf").await
    /// // or: conn.find_target(1234, "my_peer").await? [...]
    /// # });
    /// ```
    async fn find_target<T: Into<UserIdentifier> + Send, P: Into<UserIdentifier> + Send>(
        &self,
        local_user: T,
        peer: P,
    ) -> Result<SymmetricIdentifierHandleRef<'_, R>, NetworkError> {
        let account_manager = self.account_manager();
        account_manager
            .find_target_information(local_user, peer)
            .await?
            .map(move |(cid, peer)| {
                if peer.parent_icid != 0 {
                    SymmetricIdentifierHandleRef {
                        user: VirtualTargetType::ExternalGroupPeer {
                            session_cid: cid,
                            interserver_cid: peer.parent_icid,
                            peer_cid: peer.cid,
                        },
                        remote: self.remote_ref(),
                        target_username: None,
                    }
                } else {
                    SymmetricIdentifierHandleRef {
                        user: VirtualTargetType::LocalGroupPeer {
                            session_cid: cid,
                            peer_cid: peer.cid,
                        },
                        remote: self.remote_ref(),
                        target_username: None,
                    }
                }
            })
            .ok_or_else(|| NetworkError::msg("Target pair not found"))
    }

    /// Creates a proposed target from the valid local user to an unregistered peer in the network. Used when creating registration requests for peers.
    /// Currently only supports LocalGroup <-> LocalGroup peer connections
    async fn propose_target<T: Into<UserIdentifier> + Send, P: Into<UserIdentifier> + Send>(
        &self,
        local_user: T,
        peer: P,
    ) -> Result<SymmetricIdentifierHandleRef<'_, R>, NetworkError> {
        let local_cid = self.get_session_cid(local_user).await?;
        match peer.into() {
            UserIdentifier::ID(peer_cid) => Ok(SymmetricIdentifierHandleRef {
                user: VirtualTargetType::LocalGroupPeer {
                    session_cid: local_cid,
                    peer_cid,
                },
                remote: self.remote_ref(),
                target_username: None,
            }),
            UserIdentifier::Username(uname) => {
                let peer_cid = self
                    .remote_ref()
                    .account_manager()
                    .find_target_information(local_cid, uname.clone())
                    .await?
                    .map(|r| r.1.cid)
                    .unwrap_or(0);
                Ok(SymmetricIdentifierHandleRef {
                    user: VirtualTargetType::LocalGroupPeer {
                        session_cid: local_cid,
                        peer_cid,
                    },
                    remote: self.remote_ref(),
                    target_username: Some(uname),
                })
            }
        }
    }

    /// Returns a list of local group peers on the network for local_user. May or may not be registered to the user. To get a list of registered users to local_user, run [`Self::get_local_group_mutual_peers`]
    /// - limit: if None, all peers are obtained. If Some, at most the specified number of peers will be obtained
    async fn get_local_group_peers<T: Into<UserIdentifier> + Send>(
        &self,
        local_user: T,
        limit: Option<usize>,
    ) -> Result<Vec<LocalGroupPeerFullInfo>, NetworkError> {
        let local_cid = self.get_session_cid(local_user).await?;
        let command = NodeRequest::PeerCommand(PeerCommand {
            session_cid: local_cid,
            command: PeerSignal::GetRegisteredPeers {
                peer_conn_type: NodeConnectionType::LocalGroupPeerToLocalGroupServer(local_cid),
                response: None,
                limit: limit.map(|r| r as i32),
            },
        });

        let mut stream = self.send_callback_subscription(command).await?;

        while let Some(status) = stream.next().await {
            if let NodeResult::PeerEvent(PeerEvent {
                event:
                    PeerSignal::GetRegisteredPeers {
                        peer_conn_type: _,
                        response: Some(PeerResponse::RegisteredCids(peer_info, is_onlines)),
                        limit: _,
                    },
                ticket: _,
                ..
            }) = map_errors(status)?
            {
                return Ok(peer_info
                    .into_iter()
                    .zip(is_onlines.into_iter())
                    .filter_map(|(peer_info, is_online)| {
                        peer_info.map(|info| LocalGroupPeerFullInfo {
                            cid: info.cid,
                            username: Some(info.username),
                            full_name: Some(info.full_name),
                            is_online,
                        })
                    })
                    .collect());
            }
        }

        Err(NetworkError::InternalError(
            "Internal kernel stream died (get_local_group_peers)",
        ))
    }

    /// Returns a list of mutually-registered peers with the local_user
    async fn get_local_group_mutual_peers<T: Into<UserIdentifier> + Send>(
        &self,
        local_user: T,
    ) -> Result<Vec<LocalGroupPeerFullInfo>, NetworkError> {
        let local_cid = self.get_session_cid(local_user).await?;
        let command = NodeRequest::PeerCommand(PeerCommand {
            session_cid: local_cid,
            command: PeerSignal::GetMutuals {
                v_conn_type: NodeConnectionType::LocalGroupPeerToLocalGroupServer(local_cid),
                response: None,
            },
        });

        let mut stream = self.send_callback_subscription(command).await?;

        while let Some(status) = stream.next().await {
            if let NodeResult::PeerEvent(PeerEvent {
                event:
                    PeerSignal::GetMutuals {
                        v_conn_type: _,
                        response: Some(PeerResponse::RegisteredCids(peer_info, is_onlines)),
                    },
                ticket: _,
                ..
            }) = map_errors(status)?
            {
                return Ok(peer_info
                    .into_iter()
                    .zip(is_onlines.into_iter())
                    .filter_map(|(peer_info, is_online)| {
                        peer_info.map(|info| LocalGroupPeerFullInfo {
                            cid: info.cid,
                            username: Some(info.username),
                            full_name: Some(info.full_name),
                            is_online,
                        })
                    })
                    .collect());
            }
        }

        Err(NetworkError::InternalError(
            "Internal kernel stream died (get_local_group_mutual_peers)",
        ))
    }

    #[doc(hidden)]
    fn remote_ref(&self) -> &NodeRemote<R>;

    #[doc(hidden)]
    async fn get_session_cid<T: Into<UserIdentifier> + Send>(
        &self,
        local_user: T,
    ) -> Result<u64, NetworkError> {
        let account_manager = self.account_manager();
        Ok(account_manager
            .find_local_user_information(local_user)
            .await?
            .ok_or(NetworkError::InvalidRequest("User does not exist"))?)
    }
}

pub fn map_errors<R: Ratchet>(result: NodeResult<R>) -> Result<NodeResult<R>, NetworkError> {
    match result {
        NodeResult::ConnectFail(ConnectFail {
            ticket: _,
            cid_opt: _,
            error_message: err,
        }) => Err(NetworkError::Generic(err)),
        NodeResult::RegisterFailure(RegisterFailure {
            ticket: _,
            error_message: err,
        }) => Err(NetworkError::Generic(err)),
        NodeResult::InternalServerError(InternalServerError {
            ticket_opt: _,
            cid_opt: _,
            message: err,
        }) => Err(NetworkError::Generic(err)),
        NodeResult::PeerEvent(PeerEvent {
            event:
                PeerSignal::SignalError {
                    ticket: _,
                    error: err,
                    peer_connection_type: _,
                },
            ticket: _,
            ..
        }) => Err(NetworkError::Generic(err)),
        res => Ok(res),
    }
}

impl<R: Ratchet> ProtocolRemoteExt<R> for NodeRemote<R> {
    fn remote_ref(&self) -> &NodeRemote<R> {
        self
    }
}

impl<R: Ratchet> ProtocolRemoteExt<R> for ClientServerRemote<R> {
    fn remote_ref(&self) -> &NodeRemote<R> {
        &self.inner
    }
}

#[async_trait]
/// Some functions require that a target exists
pub trait ProtocolRemoteTargetExt<R: Ratchet>: TargetLockedRemote<R> {
    /// Sends a file with a custom size. The smaller the chunks, the higher the degree of scrambling, but the higher the performance cost. A chunk size of zero will use the default
    async fn send_file_with_custom_opts<T: ObjectSource>(
        &self,
        source: T,
        chunk_size: usize,
        transfer_type: TransferType,
    ) -> Result<(), NetworkError> {
        let chunk_size = if chunk_size == 0 {
            None
        } else {
            Some(chunk_size)
        };
        let session_cid = self.user().get_session_cid();
        let user = *self.user();
        let remote = self.remote();

        let mut stream = remote
            .send_callback_subscription(NodeRequest::SendObject(SendObject {
                source: Box::new(source),
                chunk_size,
                session_cid,
                v_conn_type: user,
                transfer_type,
            }))
            .await?;

        while let Some(event) = stream.next().await {
            match map_errors(event)? {
                NodeResult::ObjectTransferHandle(ObjectTransferHandle { mut handle, .. }) => {
                    return handle
                        .transfer_file()
                        .await
                        .map_err(|err| NetworkError::Generic(err.into_string()));
                }

                NodeResult::PeerEvent(PeerEvent {
                    event: PeerSignal::SignalReceived { .. },
                    ..
                }) => {}

                res => {
                    log::warn!(target: "citadel", "Invalid NodeResult for FileTransfer request received: {res:?}")
                }
            }
        }

        Err(NetworkError::InternalError("File transfer stream died"))
    }

    /// Sends a file to the provided target using the default chunking size
    async fn send_file<T: ObjectSource>(&self, source: T) -> Result<(), NetworkError> {
        self.send_file_with_custom_opts(source, 0, TransferType::FileTransfer)
            .await
    }

    /// Sends a file to the provided target using custom chunking size with local encryption.
    /// Only this local node may decrypt the information send to the adjacent node.
    async fn remote_encrypted_virtual_filesystem_push_custom_chunking<
        T: ObjectSource,
        P: Into<PathBuf> + Send,
    >(
        &self,
        source: T,
        virtual_directory: P,
        chunk_size: usize,
        security_level: SecurityLevel,
    ) -> Result<(), NetworkError> {
        self.can_use_revfs()?;
        let mut virtual_path = virtual_directory.into();
        virtual_path = prepare_virtual_path(virtual_path);
        validate_virtual_path(&virtual_path)
            .map_err(|err| NetworkError::Generic(err.into_string()))?;
        let tx_type = TransferType::RemoteEncryptedVirtualFilesystem {
            virtual_path,
            security_level,
        };
        self.send_file_with_custom_opts(source, chunk_size, tx_type)
            .await
    }

    /// Sends a file to the provided target using the default chunking size with local encryption.
    /// Only this local node may decrypt the information send to the adjacent node.
    async fn remote_encrypted_virtual_filesystem_push<T: ObjectSource, P: Into<PathBuf> + Send>(
        &self,
        source: T,
        virtual_directory: P,
        security_level: SecurityLevel,
    ) -> Result<(), NetworkError> {
        self.remote_encrypted_virtual_filesystem_push_custom_chunking(
            source,
            virtual_directory,
            0,
            security_level,
        )
        .await
    }

    /// Pulls a virtual file from the RE-VFS. If `delete_on_pull` is true, then, the virtual file
    /// will be taken from the RE-VFS
    async fn remote_encrypted_virtual_filesystem_pull<P: Into<PathBuf> + Send>(
        &self,
        virtual_directory: P,
        transfer_security_level: SecurityLevel,
        delete_on_pull: bool,
    ) -> Result<PathBuf, NetworkError> {
        self.can_use_revfs()?;
        let request = NodeRequest::PullObject(PullObject {
            v_conn: *self.user(),
            virtual_dir: virtual_directory.into(),
            delete_on_pull,
            transfer_security_level,
        });

        let mut stream = self.remote().send_callback_subscription(request).await?;

        while let Some(event) = stream.next().await {
            match map_errors(event)? {
                NodeResult::ObjectTransferHandle(ObjectTransferHandle { mut handle, .. }) => {
                    return handle
                        .receive_file()
                        .await
                        .map_err(|err| NetworkError::Generic(err.into_string()));
                }

                NodeResult::PeerEvent(PeerEvent {
                    event: PeerSignal::SignalReceived { .. },
                    ..
                }) => {}

                res => {
                    log::error!(target: "citadel", "Invalid NodeResult for REVFS FileTransfer request received: {:?}", res);
                    return Err(NetworkError::InternalError(
                        "Received invalid response from protocol",
                    ));
                }
            }
        }

        Err(NetworkError::InternalError(
            "REVFS File transfer stream died",
        ))
    }

    /// Deletes the file from the RE-VFS. If the contents are desired on delete,
    /// consider calling `Self::remote_encrypted_virtual_filesystem_pull` with the delete
    /// parameter set to true
    async fn remote_encrypted_virtual_filesystem_delete<P: Into<PathBuf> + Send>(
        &self,
        virtual_directory: P,
    ) -> Result<(), NetworkError> {
        self.can_use_revfs()?;
        let request = NodeRequest::DeleteObject(DeleteObject {
            v_conn: *self.user(),
            virtual_dir: virtual_directory.into(),
            security_level: Default::default(),
        });

        let mut stream = self.remote().send_callback_subscription(request).await?;
        while let Some(event) = stream.next().await {
            match map_errors(event)? {
                NodeResult::ReVFS(result) => {
                    return if let Some(error) = result.error_message {
                        Err(NetworkError::Generic(error))
                    } else {
                        Ok(())
                    }
                }

                evt => {
                    log::error!(target: "citadel", "Invalid NodeResult for REVFS Delete request received: {evt:?}");
                }
            }
        }

        Err(NetworkError::InternalError("REVFS Delete stream died"))
    }

    /// Connects to the peer with custom settings
    async fn connect_to_peer_custom(
        &self,
        session_security_settings: SessionSecuritySettings,
        udp_mode: UdpMode,
        peer_session_password: Option<PreSharedKey>,
    ) -> Result<PeerConnectSuccess<R>, NetworkError> {
        let session_cid = self.user().get_session_cid();
        let peer_target = self.try_as_peer_connection().await?;

        let mut stream = self
            .remote()
            .send_callback_subscription(NodeRequest::PeerCommand(PeerCommand {
                session_cid,
                command: PeerSignal::PostConnect {
                    peer_conn_type: peer_target,
                    ticket_opt: None,
                    invitee_response: None,
                    session_security_settings,
                    udp_mode,
                    session_password: peer_session_password,
                },
            }))
            .await?;

        while let Some(status) = stream.next().await {
            match map_errors(status)? {
                NodeResult::PeerChannelCreated(PeerChannelCreated {
                    ticket: _,
                    channel,
                    udp_rx_opt,
                }) => {
                    let username = self.target_username().map(ToString::to_string);
                    let remote = PeerRemote {
                        inner: self.remote().clone(),
                        peer: peer_target.as_virtual_connection(),
                        username,
                        session_security_settings,
                    };

                    return Ok(PeerConnectSuccess {
                        remote,
                        channel,
                        udp_channel_rx: udp_rx_opt,
                        incoming_object_transfer_handles: None,
                    });
                }

                NodeResult::PeerEvent(PeerEvent {
                    event:
                        PeerSignal::PostConnect {
                            invitee_response, ..
                        },
                    ..
                }) => match invitee_response {
                    Some(PeerResponse::Timeout) => {
                        return Err(NetworkError::msg("Peer did not respond in time"))
                    }
                    Some(PeerResponse::Decline) => {
                        return Err(NetworkError::msg("Peer declined to connect"))
                    }
                    _ => {}
                },

                _ => {}
            }
        }

        Err(NetworkError::InternalError(
            "Internal kernel stream died (connect_to_peer_custom)",
        ))
    }

    /// Connects to the target peer with default settings
    async fn connect_to_peer(&self) -> Result<PeerConnectSuccess<R>, NetworkError> {
        self.connect_to_peer_custom(Default::default(), Default::default(), Default::default())
            .await
    }

    /// Posts a registration request to a peer
    async fn register_to_peer(&self) -> Result<PeerRegisterStatus, NetworkError> {
        let session_cid = self.user().get_session_cid();
        let peer_target = self.try_as_peer_connection().await?;
        // TODO: Get rid of this step. Should be handled by the protocol
        let local_username = self
            .remote()
            .account_manager()
            .get_username_by_cid(session_cid)
            .await?
            .ok_or_else(|| NetworkError::msg("Unable to find username for local user"))?;
        let peer_username_opt = self.target_username().map(ToString::to_string);

        let mut stream = self
            .remote()
            .send_callback_subscription(NodeRequest::PeerCommand(PeerCommand {
                session_cid,
                command: PeerSignal::PostRegister {
                    peer_conn_type: peer_target,
                    inviter_username: local_username,
                    invitee_username: peer_username_opt,
                    ticket_opt: None,
                    invitee_response: None,
                },
            }))
            .await?;

        while let Some(status) = stream.next().await {
            if let NodeResult::PeerEvent(PeerEvent {
                event:
                    PeerSignal::PostRegister {
                        peer_conn_type: _,
                        inviter_username: _,
                        invitee_username: _,
                        ticket_opt: _,
                        invitee_response: Some(resp),
                    },
                ticket: _,
                ..
            }) = map_errors(status)?
            {
                match resp {
                    PeerResponse::Accept(..) => return Ok(PeerRegisterStatus::Accepted),
                    PeerResponse::Decline => return Ok(PeerRegisterStatus::Declined),
                    PeerResponse::Timeout => return Ok(PeerRegisterStatus::Failed { reason: Some("Timeout on register request. Peer did not accept in time. Try again later".to_string()) }),
                    _ => {}
                }
            }
        }

        Err(NetworkError::Generic(format!(
            "Internal kernel stream died (register_to_peer): {:?}",
            stream.callback_key()
        )))
    }

    /// Deregisters the currently locked target. If the target is a client to server
    /// connection, deregisters from the server. If the target is a p2p connection,
    /// deregisters the p2p
    async fn deregister(&self) -> Result<(), NetworkError> {
        if let Ok(peer_conn) = self.try_as_peer_connection().await {
            let peer_request = PeerSignal::Deregister {
                peer_conn_type: peer_conn,
            };
            let session_cid = self.user().get_session_cid();
            let request = NodeRequest::PeerCommand(PeerCommand {
                session_cid,
                command: peer_request,
            });

            let mut subscription = self.remote().send_callback_subscription(request).await?;
            while let Some(result) = subscription.next().await {
                if let NodeResult::PeerEvent(PeerEvent {
                    event: PeerSignal::DeregistrationSuccess { .. },
                    ticket: _,
                    ..
                }) = map_errors(result)?
                {
                    return Ok(());
                }
            }
        } else {
            // c2s conn
            let cid = self.user().get_session_cid();
            let request = NodeRequest::DeregisterFromHypernode(DeregisterFromHypernode {
                session_cid: cid,
                v_conn_type: *self.user(),
            });
            let mut subscription = self.remote().send_callback_subscription(request).await?;
            while let Some(result) = subscription.next().await {
                match map_errors(result)? {
                    NodeResult::DeRegistration(DeRegistration {
                        session_cid: _,
                        ticket_opt: _,
                        success: true,
                    }) => return Ok(()),
                    NodeResult::DeRegistration(DeRegistration {
                        session_cid: _,
                        ticket_opt: _,
                        success: false,
                    }) => {
                        return Err(NetworkError::msg(
                            "Unable to deregister: status=false".to_string(),
                        ))
                    }

                    _ => {}
                }
            }
        }

        Err(NetworkError::InternalError("Deregister ended unexpectedly"))
    }

    async fn disconnect(&self) -> Result<(), NetworkError> {
        if let Ok(peer_conn) = self.try_as_peer_connection().await {
            if let PeerConnectionType::LocalGroupPeer {
                session_cid,
                peer_cid: _,
            } = peer_conn
            {
                let request = NodeRequest::PeerCommand(PeerCommand {
                    session_cid,
                    command: PeerSignal::Disconnect {
                        peer_conn_type: peer_conn,
                        disconnect_response: None,
                    },
                });

                let mut subscription = self.remote().send_callback_subscription(request).await?;

                while let Some(event) = subscription.next().await {
                    if let NodeResult::PeerEvent(PeerEvent {
                        event:
                            PeerSignal::Disconnect {
                                peer_conn_type: _,
                                disconnect_response: Some(_),
                            },
                        ticket: _,
                        ..
                    }) = map_errors(event)?
                    {
                        return Ok(());
                    }
                }

                Err(NetworkError::InternalError(
                    "Unable to receive valid disconnect event",
                ))
            } else {
                Err(NetworkError::msg(
                    "External group peer functionality not enabled",
                ))
            }
        } else {
            //c2s conn
            let cid = self.user().get_session_cid();
            let request =
                NodeRequest::DisconnectFromHypernode(DisconnectFromHypernode { session_cid: cid });

            let mut subscription = self.remote().send_callback_subscription(request).await?;
            while let Some(event) = subscription.next().await {
                if let NodeResult::Disconnect(Disconnect {
                    success, message, ..
                }) = map_errors(event)?
                {
                    return if success {
                        Ok(())
                    } else {
                        Err(NetworkError::msg(message))
                    };
                }
            }

            Err(NetworkError::InternalError(
                "Unable to receive valid disconnect event",
            ))
        }
    }

    async fn create_group(
        &self,
        initial_users_to_invite: Option<Vec<UserIdentifier>>,
    ) -> Result<GroupChannel, NetworkError> {
        let session_cid = self.user().get_session_cid();

        let mut initial_users = vec![];
        // TODO: allow for custom message group options. For now, don't
        let options = MessageGroupOptions::default();
        // TODO/NOTE: default is PRIVATE mode, meaning all users in group must be registered to the owner
        // in the future, allow for private/public modes by adjusting the below. Initial users should be
        // a UserIdentifier
        if let Some(initial_users_to_invite) = initial_users_to_invite {
            for user in initial_users_to_invite {
                initial_users.push(
                    self.remote()
                        .account_manager()
                        .find_target_information(session_cid, user.clone())
                        .await
                        .map_err(|err| NetworkError::msg(err.into_string()))?
                        .ok_or_else(|| {
                            NetworkError::msg(format!(
                                "Account {user:?} not found for local user {session_cid:?}"
                            ))
                        })
                        .map(|r| r.1.cid)?,
                )
            }
        }

        let group_request = GroupBroadcast::Create {
            initial_invitees: initial_users,
            options,
        };
        let request = NodeRequest::GroupBroadcastCommand(GroupBroadcastCommand {
            session_cid,
            command: group_request,
        });
        let mut subscription = self.remote().send_callback_subscription(request).await?;
        log::error!(target: "citadel", "Create_group");
        while let Some(evt) = subscription.next().await {
            log::error!(target: "citadel", "Create_group {evt:?}");
            if let NodeResult::GroupChannelCreated(GroupChannelCreated {
                ticket: _,
                channel,
                session_cid: _,
            }) = evt
            {
                return Ok(channel);
            }
        }

        Err(NetworkError::InternalError(
            "Create_group ended unexpectedly",
        ))
    }

    /// Lists all groups that which the current peer owns
    async fn list_owned_groups(&self) -> Result<Vec<MessageGroupKey>, NetworkError> {
        let session_cid = self.user().get_session_cid();
        let cid_to_check_for = match self.try_as_peer_connection().await {
            Ok(res) => res.get_original_target_cid(),
            _ => session_cid,
        };
        let group_request = GroupBroadcast::ListGroupsFor {
            cid: cid_to_check_for,
        };
        let request = NodeRequest::GroupBroadcastCommand(GroupBroadcastCommand {
            session_cid,
            command: group_request,
        });

        let mut subscription = self.remote().send_callback_subscription(request).await?;

        while let Some(evt) = subscription.next().await {
            if let NodeResult::GroupEvent(GroupEvent {
                session_cid: _,
                ticket: _,
                event: GroupBroadcast::ListResponse { groups },
            }) = map_errors(evt)?
            {
                return Ok(groups);
            }
        }

        Err(NetworkError::InternalError(
            "List_members ended unexpectedly",
        ))
    }

    /// Begins a re-key, updating the container in the process.
    /// Returns the new key matrix version. Does not return the new key version
    /// if the rekey fails, or, if a current rekey is already executing
    async fn rekey(&self) -> Result<Option<u32>, NetworkError> {
        let request = NodeRequest::ReKey(ReKey {
            v_conn_type: *self.user(),
        });
        let mut subscription = self.remote().send_callback_subscription(request).await?;

        while let Some(evt) = subscription.next().await {
            if let NodeResult::ReKeyResult(result) = evt {
                return match result.status {
                    ReKeyReturnType::Success { version } => Ok(Some(version)),
                    ReKeyReturnType::AlreadyInProgress => Ok(None),
                    ReKeyReturnType::Failure { err } => {
                        Err(NetworkError::Generic(format!("Rekey failed: {err}")))
                    }
                };
            }
        }

        Err(NetworkError::InternalError("Rekey ended unexpectedly"))
    }

    /// Checks if the locked target is registered
    async fn is_peer_registered(&self) -> Result<bool, NetworkError> {
        let target = self.try_as_peer_connection().await?;
        if let PeerConnectionType::LocalGroupPeer {
            session_cid: local_cid,
            peer_cid,
        } = target
        {
            let peers = self.remote().get_local_group_peers(local_cid, None).await?;
            citadel_logging::info!(target: "citadel", "Checking to see if {target} is registered in {peers:?}");
            Ok(peers.iter().any(|p| p.cid == peer_cid))
        } else {
            Err(NetworkError::Generic(
                "External group peers are not supported yet".to_string(),
            ))
        }
    }

    #[doc(hidden)]
    async fn try_as_peer_connection(&self) -> Result<PeerConnectionType, NetworkError> {
        let verified_return = |user: &VirtualTargetType| {
            user.try_as_peer_connection()
                .ok_or(NetworkError::InvalidRequest("Target is not a peer"))
        };

        if self.user().get_target_cid() == 0 {
            // in this case, the user re-used a remote locked to a registration target
            // where the username was provided, but the cid was 0 (unknown).
            let peer_username = self
                .target_username()
                .ok_or_else(|| NetworkError::msg("target_cid=0, yet, no username was provided"))?;
            let session_cid = self.user().get_session_cid();
            let expected_peer_cid = self
                .remote()
                .account_manager()
                .get_persistence_handler()
                .get_cid_by_username(peer_username);
            // get the peer cid from the account manager (implying the peers are already registered).
            // fallback to the mapped cid if the peer is not registered
            let peer_cid = self
                .remote()
                .account_manager()
                .find_target_information(session_cid, peer_username)
                .await
                .map_err(|err| NetworkError::Generic(err.into_string()))?
                .map(|r| r.1.cid)
                .unwrap_or(expected_peer_cid);

            let mut user = *self.user();
            user.set_target_cid(peer_cid);
            verified_return(&user)
        } else {
            verified_return(self.user())
        }
    }

    #[doc(hidden)]
    fn can_use_revfs(&self) -> Result<(), NetworkError> {
        if let Some(sess) = self.session_security_settings() {
            if sess.crypto_params.kem_algorithm == KemAlgorithm::Kyber {
                Ok(())
            } else {
                Err(NetworkError::InvalidRequest(
                    "RE-VFS can only be used with Kyber KEM",
                ))
            }
        } else {
            Err(NetworkError::InvalidRequest(
                "RE-VFS cannot be used with this remote type",
            ))
        }
    }
}

impl<T: TargetLockedRemote<R>, R: Ratchet> ProtocolRemoteTargetExt<R> for T {}

pub mod results {
    use crate::prefabs::client::peer_connection::FileTransferHandleRx;
    use crate::prelude::{PeerChannel, UdpChannel};
    use crate::remote_ext::remote_specialization::PeerRemote;
    use citadel_io::tokio::sync::oneshot::Receiver;
    use citadel_proto::prelude::*;
    use std::fmt::Debug;

    pub struct PeerConnectSuccess<R: Ratchet> {
        pub channel: PeerChannel<R>,
        pub udp_channel_rx: Option<Receiver<UdpChannel<R>>>,
        pub remote: PeerRemote<R>,
        /// Receives incoming file/object transfer requests. The handles must be
        /// .accepted() before the file/object transfer is allowed to proceed
        pub(crate) incoming_object_transfer_handles: Option<FileTransferHandleRx>,
    }

    impl<R: Ratchet> Debug for PeerConnectSuccess<R> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PeerConnectSuccess")
                .field("channel", &self.channel)
                .field("udp_channel_rx", &self.udp_channel_rx)
                .finish()
        }
    }

    impl<R: Ratchet> PeerConnectSuccess<R> {
        /// Obtains a receiver which yields incoming file/object transfer handles
        pub fn get_incoming_file_transfer_handle(
            &mut self,
        ) -> Result<FileTransferHandleRx, NetworkError> {
            self.incoming_object_transfer_handles
                .take()
                .ok_or(NetworkError::InternalError(
                    "This function has already been called",
                ))
        }
    }

    pub enum PeerRegisterStatus {
        Accepted,
        Declined,
        Failed { reason: Option<String> },
    }

    #[derive(Clone, Debug)]
    pub struct LocalGroupPeer {
        pub cid: u64,
        pub is_online: bool,
    }

    #[derive(Clone, Debug)]
    pub struct LocalGroupPeerFullInfo {
        pub cid: u64,
        pub username: Option<String>,
        pub full_name: Option<String>,
        pub is_online: bool,
    }
}

pub mod remote_specialization {
    use crate::prelude::*;
    use std::ops::{Deref, DerefMut};

    #[derive(Debug, Clone)]
    pub struct PeerRemote<R: Ratchet> {
        pub(crate) inner: NodeRemote<R>,
        pub(crate) peer: VirtualTargetType,
        pub(crate) username: Option<String>,
        pub(crate) session_security_settings: SessionSecuritySettings,
    }

    impl<R: Ratchet> Deref for PeerRemote<R> {
        type Target = NodeRemote<R>;
        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl<R: Ratchet> DerefMut for PeerRemote<R> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }

    impl<R: Ratchet> TargetLockedRemote<R> for PeerRemote<R> {
        fn user(&self) -> &VirtualTargetType {
            &self.peer
        }
        fn remote(&self) -> &NodeRemote<R> {
            &self.inner
        }
        fn target_username(&self) -> Option<&str> {
            self.username.as_deref()
        }
        fn user_mut(&mut self) -> &mut VirtualTargetType {
            &mut self.peer
        }

        fn session_security_settings(&self) -> Option<&SessionSecuritySettings> {
            Some(&self.session_security_settings)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use crate::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use crate::prelude::*;
    use citadel_io::tokio;
    use rstest::rstest;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;

    pub struct ReceiverFileTransferKernel<R: Ratchet>(
        pub Option<NodeRemote<R>>,
        pub Arc<AtomicBool>,
    );

    #[async_trait]
    impl<R: Ratchet> NetKernel<R> for ReceiverFileTransferKernel<R> {
        fn load_remote(&mut self, node_remote: NodeRemote<R>) -> Result<(), NetworkError> {
            self.0 = Some(node_remote);
            Ok(())
        }

        async fn on_start(&self) -> Result<(), NetworkError> {
            Ok(())
        }

        async fn on_node_event_received(&self, message: NodeResult<R>) -> Result<(), NetworkError> {
            log::trace!(target: "citadel", "SERVER received {:?}", message);
            if let NodeResult::ObjectTransferHandle(ObjectTransferHandle { mut handle, .. }) =
                map_errors(message)?
            {
                let mut path = None;
                // accept the transfer
                handle
                    .accept()
                    .map_err(|err| NetworkError::msg(err.into_string()))?;

                use citadel_types::proto::ObjectTransferStatus;
                use futures::StreamExt;
                while let Some(status) = handle.next().await {
                    match status {
                        ObjectTransferStatus::ReceptionComplete => {
                            log::trace!(target: "citadel", "Server has finished receiving the file!");
                            let cmp = include_bytes!("../../resources/TheBridge.pdf");
                            let streamed_data = citadel_io::tokio::fs::read(path.clone().unwrap())
                                .await
                                .unwrap();
                            assert_eq!(
                                cmp,
                                streamed_data.as_slice(),
                                "Original data and streamed data does not match"
                            );

                            self.1.store(true, Ordering::Relaxed);
                            self.0.clone().unwrap().shutdown().await?;
                        }

                        ObjectTransferStatus::ReceptionBeginning(file_path, vfm) => {
                            path = Some(file_path);
                            assert_eq!(vfm.name, "TheBridge.pdf")
                        }

                        _ => {}
                    }
                }
            }

            Ok(())
        }

        async fn on_stop(&mut self) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    pub fn server_info<'a, R: Ratchet>(
        switch: Arc<AtomicBool>,
    ) -> (NodeFuture<'a, ReceiverFileTransferKernel<R>>, SocketAddr) {
        crate::test_common::server_test_node(ReceiverFileTransferKernel(None, switch), |_| {})
    }

    #[rstest]
    #[case(
        EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::Kyber,
        SigAlgorithm::None
    )]
    #[case(
        EncryptionAlgorithm::Kyber,
        KemAlgorithm::Kyber,
        SigAlgorithm::Falcon1024
    )]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test]
    async fn test_c2s_file_transfer(
        #[case] enx: EncryptionAlgorithm,
        #[case] kem: KemAlgorithm,
        #[case] sig: SigAlgorithm,
    ) {
        citadel_logging::setup_log();
        let client_success = &AtomicBool::new(false);
        let server_success = &Arc::new(AtomicBool::new(false));
        let (server, server_addr) = server_info::<StackedRatchet>(server_success.clone());
        let uuid = Uuid::new_v4();

        let session_security_settings = SessionSecuritySettingsBuilder::default()
            .with_crypto_params(enx + kem + sig)
            .build()
            .unwrap();

        let server_connection_settings =
            DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, uuid)
                .with_session_security_settings(session_security_settings)
                .disable_udp()
                .build()
                .unwrap();

        let client_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            |connection| async move {
                log::trace!(target: "citadel", "***CLIENT LOGIN SUCCESS :: File transfer next ***");
                connection
                    .send_file_with_custom_opts(
                        "../resources/TheBridge.pdf",
                        32 * 1024,
                        TransferType::FileTransfer,
                    )
                    .await
                    .unwrap();
                log::trace!(target: "citadel", "***CLIENT FILE TRANSFER SUCCESS***");
                client_success.store(true, Ordering::Relaxed);
                connection.shutdown_kernel().await
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        let _ = joined.await.unwrap();

        assert!(client_success.load(Ordering::Relaxed));
        assert!(server_success.load(Ordering::Relaxed));
    }
}
