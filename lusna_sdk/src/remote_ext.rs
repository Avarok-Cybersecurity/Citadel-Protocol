use crate::prelude::*;
use std::path::PathBuf;
use futures::StreamExt;
use crate::remote_ext::user_ids::{TargetLockedRemote, SymmetricIdentifierHandleRef};
use hyxe_net::auth::AuthenticationRequest;
use crate::prelude::results::{PeerConnectSuccess, PeerRegisterStatus};
use crate::remote_ext::results::HyperlanPeer;
use std::time::Duration;

pub(crate) mod user_ids {
    use crate::prelude::*;
    use std::ops::{Deref, DerefMut};

    #[derive(Debug)]
    /// A reference to a user identifier
    pub struct SymmetricIdentifierHandleRef<'a> {
        pub(crate) user: VirtualTargetType,
        pub(crate) remote: &'a mut NodeRemote,
        pub(crate) target_username: Option<String>
    }

    impl SymmetricIdentifierHandleRef<'_> {
        pub fn into_owned(self) -> SymmetricIdentifierHandle {
            SymmetricIdentifierHandle {
                user: self.user,
                remote: self.remote.clone(),
                target_username: self.target_username
            }
        }
    }

    #[derive(Clone, Debug)]
    /// A convenience structure for executing commands that depend on a specific registered user
    pub struct SymmetricIdentifierHandle {
        user: VirtualTargetType,
        remote: NodeRemote,
        target_username: Option<String>
    }

    pub trait TargetLockedRemote {
        fn user(&self) -> &VirtualTargetType;
        fn remote(&mut self) -> &mut NodeRemote;
        fn target_username(&self) -> Option<&String>;
        fn user_mut(&mut self) -> &mut VirtualTargetType;
    }

    impl TargetLockedRemote for SymmetricIdentifierHandleRef<'_> {
        fn user(&self) -> &VirtualTargetType {
            &self.user
        }
        fn remote(&mut self) -> &mut NodeRemote {
            self.remote
        }
        fn target_username(&self) -> Option<&String> { self.target_username.as_ref() }

        fn user_mut(&mut self) -> &mut VirtualTargetType {
            &mut self.user
        }
    }

    impl TargetLockedRemote for SymmetricIdentifierHandle {
        fn user(&self) -> &VirtualTargetType {
            &self.user
        }
        fn remote(&mut self) -> &mut NodeRemote {
            &mut self.remote
        }
        fn target_username(&self) -> Option<&String> { self.target_username.as_ref() }

        fn user_mut(&mut self) -> &mut VirtualTargetType {
            &mut self.user
        }
    }

    impl From<SymmetricIdentifierHandleRef<'_>> for SymmetricIdentifierHandle {
        fn from(this: SymmetricIdentifierHandleRef<'_>) -> Self {
            this.into_owned()
        }
    }

    impl Deref for SymmetricIdentifierHandle {
        type Target = NodeRemote;

        fn deref(&self) -> &Self::Target {
            &self.remote
        }
    }

    impl Deref for SymmetricIdentifierHandleRef<'_> {
        type Target = NodeRemote;

        fn deref(&self) -> &Self::Target {
            self.remote
        }
    }

    impl DerefMut for SymmetricIdentifierHandle {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.remote
        }
    }

    impl DerefMut for SymmetricIdentifierHandleRef<'_> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.remote
        }
    }
}

/// Contains the elements required to communicate with the adjacent node
pub struct ConnectSuccess {
    /// An interface to send ordered, reliable, and encrypted messages
    pub channel: PeerChannel,
    /// Only available if UdpMode was enabled at the beginning of a session
    pub udp_channel_rx: Option<tokio::sync::oneshot::Receiver<UdpChannel>>,
    /// Contains the Google auth minted at the central server (if the central server enabled it), as well as any other services enabled by the central server
    pub services: ServicesObject,
    pub cid: u64
}

/// Contains the elements entailed by a successful registration
pub struct RegisterSuccess {}

#[async_trait]
/// Endows the ['HdpServerRemote'] with additional functions
pub trait ProtocolRemoteExt: Remote {
    /// Registers with custom settings
    /// Returns a ticket which is used to uniquely identify the request in the protocol
    async fn register<T: std::net::ToSocketAddrs + Send, R: Into<String> + Send, V: Into<String> + Send, K: Into<SecBuffer> + Send>(&mut self, addr: T, full_name: R, username: V, proposed_password: K, default_security_settings: SessionSecuritySettings) -> Result<RegisterSuccess, NetworkError> {
        let creds = ProposedCredentials::new_register(full_name, username, proposed_password.into()).await?;
        let register_request = NodeRequest::RegisterToHypernode(addr.to_socket_addrs()?.next().ok_or(NetworkError::InternalError("Invalid socket addr"))?, creds, default_security_settings);

        match map_errors(self.send_callback(register_request).await?)? {
            NodeResult::RegisterOkay(..) => Ok(RegisterSuccess {}),
            res => Err(NetworkError::msg(format!("An unexpected response occurred: {:?}", res)))
        }
    }

    /// Registers using the default settings. The default uses No Google FCM keys and the default session security settings
    /// Returns a ticket which is used to uniquely identify the request in the protocol
    async fn register_with_defaults<T: std::net::ToSocketAddrs + Send, R: Into<String> + Send, V: Into<String> + Send, K: Into<SecBuffer> + Send>(&mut self, addr: T, full_name: R, username: V, proposed_password: K) -> Result<RegisterSuccess, NetworkError> {
        self.register(addr, full_name, username, proposed_password, Default::default()).await
    }

    /// Connects with custom settings
    /// Returns a ticket which is used to uniquely identify the request in the protocol
    async fn connect(&mut self, auth: AuthenticationRequest, connect_mode: ConnectMode, udp_mode: UdpMode, keep_alive_timeout: Option<Duration>, session_security_settings: SessionSecuritySettings) -> Result<ConnectSuccess, NetworkError> {
        //let fcm_keys = fcm_keys.or_else(||cnac.get_fcm_keys()); // use the specified keys, or else get the fcm keys created during the registration phase

        let connect_request = NodeRequest::ConnectToHypernode(auth, connect_mode, udp_mode, keep_alive_timeout.map(|r| r.as_secs()), session_security_settings);

        match map_errors(self.send_callback(connect_request).await?)? {
            NodeResult::ConnectSuccess(_, cid, _, _, _, services, _, channel, udp_channel_rx) => Ok(ConnectSuccess { channel, udp_channel_rx, services, cid }),
            NodeResult::ConnectFail(_, _, err) => Err(NetworkError::Generic(err)),
            res => Err(NetworkError::msg(format!("[connect] An unexpected response occurred: {:?}", res)))
        }
    }

    /// Connects with the default settings
    /// If FCM keys were created during the registration phase, then those keys will be used for the session. If new FCM keys need to be used, consider using [`Self::connect`]
    async fn connect_with_defaults(&mut self, auth: AuthenticationRequest) -> Result<ConnectSuccess, NetworkError> {
        self.connect(auth, Default::default(), Default::default(), None, Default::default()).await
    }

    /// Creates a valid target identifier used to make protocol requests. Raw user IDs or usernames can be used
    /// ```
    /// use hyxe_net::prelude::*;
    /// remote.find_target("my_account", "my_peer").await?.send_file("/path/to/file.pdf").await?;
    /// // or: remote.find_target(1234, "my_peer").await? [...]
    /// ```
    async fn find_target<T: Into<UserIdentifier> + Send, R: Into<UserIdentifier> + Send>(&mut self, local_user: T, peer: R) -> Result<SymmetricIdentifierHandleRef<'_>, NetworkError> {
        let account_manager = self.account_manager();
        account_manager.find_target_information(local_user, peer).await?.map(move |(cid, peer)| if peer.parent_icid != 0 {
            SymmetricIdentifierHandleRef { user: VirtualTargetType::HyperLANPeerToHyperWANPeer(cid, peer.parent_icid, peer.cid), remote: self.remote_ref_mut(), target_username: None }
        } else {
            SymmetricIdentifierHandleRef { user: VirtualTargetType::HyperLANPeerToHyperLANPeer(cid, peer.cid), remote: self.remote_ref_mut(), target_username: None }
        }).ok_or_else(|| NetworkError::msg("Target pair not found"))
    }

    /// Creates a proposed target from the valid local user to an unregistered peer in the network. Used when creating registration requests for peers.
    /// Currently only supports HyperLAN <-> HyperLAN peer connections
    async fn propose_target<T: Into<UserIdentifier> + Send, P: Into<UserIdentifier> + Send>(&mut self, local_user: T, peer: P) -> Result<SymmetricIdentifierHandleRef<'_>, NetworkError> {
        let local_cid = self.get_implicated_cid(local_user).await?;
        match peer.into() {
            UserIdentifier::ID(peer_cid) => {
                Ok(SymmetricIdentifierHandleRef { user: VirtualTargetType::HyperLANPeerToHyperLANPeer(local_cid, peer_cid), remote: self.remote_ref_mut(), target_username: None })
            }
            UserIdentifier::Username(uname) => {
                Ok(SymmetricIdentifierHandleRef { user: VirtualTargetType::HyperLANPeerToHyperLANPeer(local_cid, 0), remote: self.remote_ref_mut(), target_username: Some(uname) })
            }
        }
    }

    /// Returns a list of hyperlan peers on the network for local_user. May or may not be registered to the user. To get a list of registered users to local_user, run [`Self::get_hyperlan_mutual_peers`]
    /// - limit: if None, all peers are obtained. If Some, at most the specified number of peers will be obtained
    async fn get_hyperlan_peers<T: Into<UserIdentifier> + Send>(&mut self, local_user: T, limit: Option<usize>) -> Result<Vec<HyperlanPeer>, NetworkError> {
        let local_cid = self.get_implicated_cid(local_user).await?;
        let command = NodeRequest::PeerCommand(local_cid, PeerSignal::GetRegisteredPeers(HypernodeConnectionType::HyperLANPeerToHyperLANServer(local_cid), None, limit.map(|r| r as i32)));

        let mut stream = self.send_callback_subscription(command).await?;

        while let Some(status) = stream.next().await {
            match map_errors(status)? {
                NodeResult::PeerEvent(PeerSignal::GetRegisteredPeers(_, Some(PeerResponse::RegisteredCids(cids, is_onlines)), _), _) => {
                    return Ok(cids.into_iter().zip(is_onlines.into_iter()).map(|(cid, is_online)| HyperlanPeer { cid, is_online }).collect())
                }

                _ => {}
            }
        }

        Err(NetworkError::InternalError("Internal kernel stream died"))
    }

    /// Returns a list of mutually-registered peers with the local_user
    async fn get_hyperlan_mutual_peers<T: Into<UserIdentifier> + Send>(&mut self, local_user: T) -> Result<Vec<HyperlanPeer>, NetworkError> {
        let local_cid = self.get_implicated_cid(local_user).await?;
        let command = NodeRequest::PeerCommand(local_cid, PeerSignal::GetMutuals(HypernodeConnectionType::HyperLANPeerToHyperLANServer(local_cid), None));

        let mut stream = self.send_callback_subscription(command).await?;

        while let Some(status) = stream.next().await {
            match map_errors(status)? {
                NodeResult::PeerEvent(PeerSignal::GetMutuals(_, Some(PeerResponse::RegisteredCids(cids, is_onlines))), _) => {
                    return Ok(cids.into_iter().zip(is_onlines.into_iter()).map(|(cid, is_online)| HyperlanPeer { cid, is_online }).collect())
                }

                _ => {}
            }
        }

        Err(NetworkError::InternalError("Internal kernel stream died"))
    }

    #[doc(hidden)]
    fn remote_ref_mut(&mut self) -> &mut NodeRemote;

    #[doc(hidden)]
    async fn get_implicated_cid<T: Into<UserIdentifier> + Send>(&mut self, local_user: T) -> Result<u64, NetworkError> {
        let account_manager = self.account_manager();
        Ok(account_manager.find_local_user_information(local_user).await?.ok_or(NetworkError::InvalidRequest("User does not exist"))?)
    }
}

pub(crate) fn map_errors(result: NodeResult) -> Result<NodeResult, NetworkError> {
    match result {
        NodeResult::InternalServerError(_, err) => Err(NetworkError::Generic(err)),
        NodeResult::PeerEvent(PeerSignal::SignalError(_, err), _) => Err(NetworkError::Generic(err)),
        res => Ok(res)
    }
}

impl ProtocolRemoteExt for NodeRemote {
    fn remote_ref_mut(&mut self) -> &mut NodeRemote {
        self
    }
}

#[async_trait]
/// Some functions require that a target exists
pub trait ProtocolRemoteTargetExt: TargetLockedRemote {
    /// Sends a file with a custom size. The smaller the chunks, the higher the degree of scrambling, but the higher the performance cost. A chunk size of zero will use the default
    async fn send_file_with_custom_chunking<T: Into<PathBuf> + Send>(&mut self, path: T, chunk_size: usize) -> Result<(), NetworkError> {
        let chunk_size = if chunk_size == 0 { None } else { Some(chunk_size) };
        let implicated_cid = self.user().get_implicated_cid();
        let user = *self.user();
        let remote = self.remote();

        let result = remote.send_callback(NodeRequest::SendFile(path.into(), chunk_size, implicated_cid, user)).await?;
        match map_errors(result)? {
            NodeResult::ObjectTransferHandle(_ticket, mut handle) => {
                while let Some(res) = handle.next().await {
                    log::trace!(target: "lusna", "Client received RES {:?}", res);
                    if let ObjectTransferStatus::TransferComplete = res {
                        return Ok(())
                    }
                }
            }

            res => log::error!(target: "lusna", "Invalid HdpServerResult for FileTransfer request received: {:?}", res)
        }

        Err(NetworkError::InternalError("File transfer stream died"))
    }

    /// Sends a file to the provided target using the default chunking size
    async fn send_file<T: Into<PathBuf> + Send>(&mut self, path: T) -> Result<(), NetworkError> {
        self.send_file_with_custom_chunking(path,0).await
    }

    /// Connects to the peer with custom settings
    async fn connect_to_peer_custom(&mut self, session_security_settings: SessionSecuritySettings, udp_mode: UdpMode) -> Result<PeerConnectSuccess, NetworkError> {
        let implicated_cid = self.user().get_implicated_cid();
        let peer_target = self.try_as_peer_connection().await?;

        let mut stream = self.remote().send_callback_subscription(NodeRequest::PeerCommand(implicated_cid, PeerSignal::PostConnect(peer_target, None, None, session_security_settings, udp_mode))).await?;

        while let Some(status) = stream.next().await {
            match map_errors(status)? {
                NodeResult::PeerChannelCreated(_, channel, udp_rx_opt) => {
                    return Ok(PeerConnectSuccess { channel, udp_rx_opt })
                }

                NodeResult::PeerEvent(PeerSignal::PostConnect(_, _, Some(PeerResponse::Decline), ..), ..) => {
                    return Err(NetworkError::msg("Peer declined to connect"))
                }

                _ => {}
            }
        }

        Err(NetworkError::InternalError("Internal kernel stream died"))
    }

    /// Connects to the target peer with default settings
    async fn connect_to_peer(&mut self) -> Result<PeerConnectSuccess, NetworkError> {
        self.connect_to_peer_custom(Default::default(), Default::default()).await
    }

    /// Posts a registration request to a peer
    async fn register_to_peer(&mut self) -> Result<PeerRegisterStatus, NetworkError> {
        let implicated_cid = self.user().get_implicated_cid();
        let peer_target = self.try_as_peer_connection().await?;
        // TODO: Get rid of this step. Should be handled by the protocol
        let local_username = self.remote().account_manager().get_username_by_cid(implicated_cid).await?.ok_or_else(||NetworkError::msg("Unable to find username for local user"))?;
        let peer_username_opt = self.target_username().cloned();

        let mut stream = self.remote().send_callback_subscription(NodeRequest::PeerCommand(implicated_cid, PeerSignal::PostRegister(peer_target, local_username, peer_username_opt, None, None))).await?;

        while let Some(status) = stream.next().await {
            match map_errors(status)? {
                NodeResult::PeerEvent(PeerSignal::PostRegister(_, _, _, _, Some(resp)), _) => {
                    match resp {
                        PeerResponse::Accept(..) => return Ok(PeerRegisterStatus::Accepted),
                        PeerResponse::Decline => return Ok(PeerRegisterStatus::Declined),
                        PeerResponse::Timeout => return Ok(PeerRegisterStatus::Failed { reason: Some("Timeout on register request. Peer did not accept in time. Try again later".to_string()) }),
                        _ => {}
                    }
                }

                _ => {}
            }
        }

        Err(NetworkError::InternalError("Internal kernel stream died"))
    }

    #[doc(hidden)]
    async fn try_as_peer_connection(&mut self) -> Result<PeerConnectionType, NetworkError> {
        let verified_return = |user: &VirtualTargetType| {
            user.try_as_peer_connection().ok_or(NetworkError::InvalidRequest("Target is not a peer"))
        };

        if self.user().get_target_cid() == 0 {
            // in this case, the user re-used a remote locked to a registration target
            // where the username was provided, but the cid was 0 (unknown).
            let peer_username = self.target_username().ok_or_else(|| NetworkError::msg("target_cid=0, yet, no username was provided"))?.clone();
            let implicated_cid = self.user().get_implicated_cid();
            let peer_cid = self.remote().account_manager().find_target_information(implicated_cid, peer_username).await
                .map_err(|err| NetworkError::Generic(err.into_string()))?
                .map(|r| r.1.cid)
                .unwrap_or(0);

            self.user_mut().set_target_cid(peer_cid);
            verified_return(self.user())
        } else {
            verified_return(self.user())
        }
    }
}

impl<T: TargetLockedRemote> ProtocolRemoteTargetExt for T {}

pub mod results {
    use crate::prelude::{PeerChannel, UdpChannel};
    use tokio::sync::oneshot::Receiver;

    #[derive(Debug)]
    pub struct PeerConnectSuccess {
        pub channel: PeerChannel,
        pub udp_rx_opt: Option<Receiver<UdpChannel>>
    }

    pub enum PeerRegisterStatus {
        Accepted,
        Declined,
        Failed { reason: Option<String> }
    }

    pub struct HyperlanPeer {
        pub cid: u64,
        pub is_online: bool
    }
}

pub mod remote_specialization {
    use crate::prelude::{NodeRemote, VirtualTargetType};
    use crate::prelude::user_ids::TargetLockedRemote;

    pub struct PeerRemote {
        inner: NodeRemote,
        peer: VirtualTargetType,
        username: Option<String>
    }

    impl TargetLockedRemote for PeerRemote {
        fn user(&self) -> &VirtualTargetType {
            &self.peer
        }

        fn remote(&mut self) -> &mut NodeRemote {
            &mut self.inner
        }

        fn target_username(&self) -> Option<&String> {
            self.username.as_ref()
        }

        fn user_mut(&mut self) -> &mut VirtualTargetType {
            &mut self.peer
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use crate::builder::node_builder::{NodeBuilder, NodeFuture};
    use crate::prelude::{ProtocolRemoteTargetExt, NetKernel, NodeRemote, NetworkError, NodeResult};
    use crate::remote_ext::map_errors;
    use rstest::rstest;
    use futures::StreamExt;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use crate::prelude::*;
    use uuid::Uuid;

    pub struct ServerFileTransferKernel(Option<NodeRemote>);

    #[async_trait]
    impl NetKernel for ServerFileTransferKernel {
        fn load_remote(&mut self, node_remote: NodeRemote) -> Result<(), NetworkError> {
            self.0 = Some(node_remote);
            Ok(())
        }

        async fn on_start(&self) -> Result<(), NetworkError> {
            Ok(())
        }

        async fn on_node_event_received(&self, message: NodeResult) -> Result<(), NetworkError> {
            log::trace!(target: "lusna", "SERVER received {:?}", message);
            if let NodeResult::ObjectTransferHandle(_, mut handle) = map_errors(message)? {
                let mut path = None;
                while let Some(status) = handle.next().await {
                    match status {
                        ObjectTransferStatus::ReceptionComplete => {
                            log::trace!(target: "lusna", "Server has finished receiving the file!");
                            SERVER_SUCCESS.store(true, Ordering::Relaxed);
                            let cmp = include_bytes!("../../resources/TheBridge.pdf");
                            let streamed_data = tokio::fs::read(path.clone().unwrap()).await.unwrap();
                            assert_eq!(cmp, streamed_data.as_slice(), "Original data and streamed data does not match");
                            self.0.clone().unwrap().shutdown().await?;
                        }

                        ObjectTransferStatus::ReceptionBeginning(file_path, vfm) => {
                            path = Some(file_path);
                            assert_eq!(vfm.get_target_name(), "TheBridge.pdf")
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

    pub fn server_info<'a>() -> (NodeFuture<'a, ServerFileTransferKernel>, SocketAddr) {
        let port = crate::test_common::get_unused_tcp_port();
        let bind_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap();
        let server = crate::test_common::server_test_node(bind_addr, ServerFileTransferKernel(None));
        (server, bind_addr)
    }

    static SERVER_SUCCESS: AtomicBool = AtomicBool::new(false);

    #[rstest]
    #[timeout(std::time::Duration::from_secs(90))]
    #[tokio::test]
    async fn test_c2s_file_transfer() {
        let _ = lusna_logging::setup_log();

        static CLIENT_SUCCESS: AtomicBool = AtomicBool::new(false);
        let (server, server_addr) = server_info();
        let uuid = Uuid::new_v4();

        let client_kernel = SingleClientServerConnectionKernel::new_passwordless_defaults(uuid, server_addr, |_channel, mut remote| async move {
            log::trace!(target: "lusna", "***CLIENT LOGIN SUCCESS :: File transfer next ***");
            remote.send_file_with_custom_chunking("../resources/TheBridge.pdf", 32*1024).await.unwrap();
            log::trace!(target: "lusna", "***CLIENT FILE TRANSFER SUCCESS***");
            CLIENT_SUCCESS.store(true, Ordering::Relaxed);
            remote.shutdown_kernel().await
        });

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        let _ = joined.await.unwrap();

        assert!(CLIENT_SUCCESS.load(Ordering::Relaxed));
        assert!(SERVER_SUCCESS.load(Ordering::Relaxed));
    }
}