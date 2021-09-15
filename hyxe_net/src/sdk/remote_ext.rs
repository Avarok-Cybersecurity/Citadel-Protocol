use crate::prelude::{HdpServerRemote, SessionSecuritySettings, UdpMode, HdpServerResult};
use crate::error::NetworkError;
use crate::hdp::hdp_server::{HdpServerRequest, ConnectMode};
use hyxe_user::proposed_credentials::ProposedCredentials;
use hyxe_crypt::prelude::SecBuffer;
use hyxe_crypt::fcm::keys::FcmKeys;
use crate::hdp::peer::channel::{PeerChannel, UdpChannel};
use hyxe_user::external_services::ServicesObject;
use std::path::PathBuf;
use crate::hdp::state_container::VirtualTargetType;
use crate::hdp::file_transfer::FileTransferStatus;
use hyxe_user::prelude::UserIdentifier;

pub struct ConnectSuccess {
    /// An interface to send ordered, reliable, and encrypted messages
    pub channel: PeerChannel,
    /// Only available if UdpMode was enabled at the beginning of a session
    pub udp_channel_rx: Option<tokio::sync::oneshot::Receiver<UdpChannel>>,
    /// Contains the Google auth minted at the central server (if the central server enabled it), as well as any other services enabled by the central server
    pub services: ServicesObject,
}

pub struct RegisterSuccess {}

impl HdpServerRemote {
    /// Registers with custom settings
    /// Returns a ticket which is used to uniquely identify the request in the protocol
    pub async fn register<T: std::net::ToSocketAddrs, R: Into<String> + Send, V: Into<String> + Send, K: Into<SecBuffer>>(&mut self, addr: T, full_name: R, username: V, proposed_password: K, fcm_keys: Option<FcmKeys>, default_security_settings: SessionSecuritySettings) -> Result<RegisterSuccess, NetworkError> {
        let creds = ProposedCredentials::new_register(full_name, username, proposed_password.into()).await?;
        let register_request = HdpServerRequest::RegisterToHypernode(addr.to_socket_addrs()?.next().ok_or_else(||NetworkError::InternalError("Invalid socket addr"))?, creds, fcm_keys, default_security_settings);

        match self.send_callback(register_request).await? {
            HdpServerResult::RegisterOkay(..) => Ok(RegisterSuccess {}),
            HdpServerResult::RegisterFailure(_, err) => Err(NetworkError::Generic(err)),
            HdpServerResult::InternalServerError(_, err) => Err(NetworkError::Generic(err)),
            _ => Err(NetworkError::msg("An unexpected response occurred"))
        }
    }

    /// Registers using the default settings. The default uses No Google FCM keys and the default session security settings
    /// Returns a ticket which is used to uniquely identify the request in the protocol
    pub async fn register_with_defaults<T: std::net::ToSocketAddrs, R: Into<String> + Send, V: Into<String> + Send, K: Into<SecBuffer>>(&mut self, addr: T, full_name: R, username: V, proposed_password: K) -> Result<RegisterSuccess, NetworkError> {
        self.register(addr, full_name, username, proposed_password, None, Default::default()).await
    }

    /// Connects with custom settings
    /// Returns a ticket which is used to uniquely identify the request in the protocol
    pub async fn connect<T: Into<String> + Send, V: Into<SecBuffer>>(&mut self, username: T, password: V, connect_mode: ConnectMode, fcm_keys: Option<FcmKeys>, udp_mode: UdpMode, keep_alive_timeout_sec: Option<u32>, session_security_settings: SessionSecuritySettings) -> Result<ConnectSuccess, NetworkError> {
        let username = username.into();

        let cnac = self.account_manager().get_client_by_username(&username).await?.ok_or_else(||NetworkError::msg("Username does not exist locally (is the account registered yet?)"))?;
        let _ = cnac.get_static_auxiliary_hyper_ratchet().verify_level(Some(session_security_settings.security_level))?;
        let creds = cnac.generate_connect_credentials(password.into()).await?;
        let cid = cnac.get_cid();

        let fcm_keys = fcm_keys.or_else(||cnac.get_fcm_keys()); // use the specified keys, or else get the fcm keys created during the registration phase

        let connect_request = HdpServerRequest::ConnectToHypernode(cid, creds, connect_mode, fcm_keys, udp_mode, keep_alive_timeout_sec, session_security_settings);

        match self.send_callback(connect_request).await? {
            HdpServerResult::ConnectSuccess(_,_,_,_,_,_,services,_,channel,udp_channel_rx) => Ok(ConnectSuccess { channel, udp_channel_rx, services }),
            HdpServerResult::ConnectFail(_, _, err) => Err(NetworkError::Generic(err)),
            HdpServerResult::InternalServerError(_, err) => Err(NetworkError::Generic(err)),
            _ => Err(NetworkError::msg("An unexpected response occurred"))
        }
    }

    /// Connects with the default settings
    /// If FCM keys were created during the registration phase, then those keys will be used for the session. If new FCM keys need to be used, consider using [`Self::connect`]
    pub async fn connect_with_defaults<T: Into<String> + Send, V: Into<SecBuffer>>(&mut self, username: T, password: V) -> Result<ConnectSuccess, NetworkError> {
        self.connect(username, password, Default::default(), None, Default::default(), None, Default::default()).await
    }

    /// Sends a file with a custom size. The smaller the chunks, the higher the degree of scrambling, but the higher the performance penalty. A chunk size of zero will use the default
    pub async fn send_file_with_custom_chunking<T: Into<PathBuf>>(&mut self, path: T, target: VirtualTargetType, chunk_size: usize) -> Result<(), NetworkError> {
        let chunk_size = if chunk_size == 0 { None } else { Some(chunk_size) };
        let mut stream = self.send_callback_stream(HdpServerRequest::SendFile(path.into(), chunk_size,target.get_implicated_cid(), target)).await?;
        use futures::StreamExt;

        while let Some(item) = stream.next().await {
            match item {
                HdpServerResult::FileTransferStatus(_, _, _, status) => {
                    match status {
                        FileTransferStatus::TransferComplete => {
                            return Ok(())
                        }

                        FileTransferStatus::Fail(err) => {
                            return Err(NetworkError::Generic(err))
                        }

                        _ => {}
                    }
                }

                HdpServerResult::InternalServerError(_, err) => {
                    return Err(NetworkError::Generic(err))
                }

                _ => {}
            }
        }

        Err(NetworkError::InternalError("Unable to send file"))
    }

    /// Sends a file to the provided target using the default chunking size
    pub async fn send_file<T: Into<PathBuf>>(&mut self, path: T, target: VirtualTargetType) -> Result<(), NetworkError> {
        self.send_file_with_custom_chunking(path, target, 0).await
    }

    /// Creates a valid target identifier used to make protocol requests. Raw user IDs or usernames can be used
    /// ```
    /// use hyxe_net::prelude::*;
    /// let target: VirtualTargetType = remote.find_target("alice", "bob").unwrap();
    /// // or: remote.find_target(1234, "bob")
    /// remote.send_file("/path/to/file.pdf", target).await.unwrap();
    /// ```
    pub async fn find_target(&self, local_user: impl Into<UserIdentifier>, peer: impl Into<UserIdentifier>) -> Result<VirtualTargetType, NetworkError> {
        self.account_manager().find_target_information(local_user, peer).await?.map(|(cid, peer)| if peer.parent_icid != 0 {
            VirtualTargetType::HyperLANPeerToHyperWANPeer(cid, peer.parent_icid, peer.cid)
        } else {
            VirtualTargetType::HyperLANPeerToHyperLANPeer(cid, peer.cid)
        }).ok_or_else(|| NetworkError::msg("Target pair not found"))
    }
}