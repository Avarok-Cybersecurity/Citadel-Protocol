use crate::prelude::{NodeRequest, NetworkError, UdpMode, SessionSecuritySettings, ConnectMode, ProposedCredentials, Remote, PeerSignal, UserIdentifier, PeerConnectionType, FcmPostRegister};
use hyxe_net::auth::AuthenticationRequest;
use std::time::Duration;
use std::net::ToSocketAddrs;

/// Convenience for building registration requests to *allow* future connection requests to a server
pub struct RegistrationBuilder {
    registration_security_settings: Option<SessionSecuritySettings>
}

impl RegistrationBuilder {
    /// Sets the registration security settings. See: [`SessionSecuritySettingsBuilder`].
    /// Note: as opposed to the session security settings, which controls the maximum
    /// possible level of encryption for any given message for that session, the registration
    /// security settings controls the maximum possible encryption level for the static local symmetric
    /// key matrix, and as a result, all following symmetric key matrices that occur during the connection
    /// and session phases. Additionally, all future connection-related packets get encrypted to the maximum
    /// possible level as determined by the registration security settings. This ensures that a hacker
    /// would have to discover all keys created in the registration process before being able to discover the
    /// keys used during the first key exchange in the connection phase.
    ///
    /// Example: if [`SecurityLevel::Medium`] is used for registration, then, only [`SecurityLevel::Low`]
    /// or [`SecurityLevel::Medium`] may be used during the connection phase.
    pub fn registration_security_settings(mut self, security_settings: SessionSecuritySettings) -> Self {
        self.registration_security_settings = Some(security_settings);
        self
    }

    pub fn build<T: ToSocketAddrs>(self, server_addr: T, proposed_credentials: ProposedCredentials) -> Result<NodeRequest, NetworkError> {
        self.validate()?;
        let addr = server_addr.to_socket_addrs().map_err(|err| NetworkError::Generic(err.to_string()))?
            .next().ok_or(NetworkError::InvalidRequest("No addresses found"))?;
        let fcm_keys = None;
        let sess_security_settings = self.registration_security_settings.unwrap_or_default();
        Ok(NodeRequest::RegisterToHypernode(addr, proposed_credentials, fcm_keys, sess_security_settings))
    }

    fn validate(&self) -> Result<(), NetworkError> {
        Ok(())
    }
}


#[derive(Default, Clone, Debug)]
/// Convenience for building connection requests to servers to whom one is already registered to
pub struct ConnectionBuilder {
    udp_mode: Option<UdpMode>,
    session_security_settings: Option<SessionSecuritySettings>,
    connect_mode: Option<ConnectMode>,
    keep_alive_interval_secs: Option<u64>
}

impl ConnectionBuilder {
    /// Sets the UdpMode for this session. If enabled, then, the session will have
    /// a simultaneous UDP-based unreliable and unordered connection to the server.
    /// This channel can be retrieved on connection success.
    ///
    /// Default is enabled
    pub fn udp_mode(mut self, udp_mode: UdpMode) -> Self {
        self.udp_mode = Some(udp_mode);
        self
    }

    /// Sets the session security settings for this session. See: [`SessionSecuritySettingsBuilder`]
    pub fn session_security_settings(mut self, security_settings: SessionSecuritySettings) -> Self {
        self.session_security_settings = Some(security_settings);
        self
    }

    /// Sets the connect mode for this session. If using [`ConnectMode::Fetch`], then,
    /// there will be no channel to server for communication, and instead, the protocol
    /// will only fetch the latest mailbox items, and thereafter, immediately disconnecting.
    pub fn connect_mode(mut self, connect_mode: ConnectMode) -> Self {
        self.connect_mode = Some(connect_mode);
        self
    }

    /// Sets the keep alive interval. If set to zero, then, the protocol disables the keep alive system.
    /// If left at None, then, the protocol uses the default interval.
    ///
    /// Only set this value if you know what you're doing. Increasing the keep alive frequency
    /// may be useful under very specific circumstances where a firewall may shut down idled
    /// connections automatically.
    pub fn keep_alive_interval(mut self, keep_alive_interval: Duration) -> Self {
        self.keep_alive_interval_secs = Some(keep_alive_interval.as_secs());
        self
    }

    /// Given the authentication request, crates the final request used to begin connecting to the server.
    /// Note: the returned request does nothing by itself; it must be submitted via the [`NodeRemote`] in
    /// order to have an affect
    pub async fn build(self, authentication_request: AuthenticationRequest, remote: &mut impl Remote) -> Result<NodeRequest, NetworkError> {
        let udp_mode = self.udp_mode.unwrap_or_default();
        let sess_sec_settings = self.session_security_settings.unwrap_or_default();
        let connect_mode = self.connect_mode.unwrap_or_default();
        let ka = self.keep_alive_interval_secs;
        let fcm_keys = None;

        if let AuthenticationRequest::Credentialed { id, .. } = &authentication_request {
            // validate that the security level is valid
            let cnac = remote.account_manager().find_cnac_by_identifier(id.clone()).await
                .map_err(|err| NetworkError::Generic(err.into_string()))?
                .ok_or_else(|| NetworkError::Generic(format!("User {:?} does not exist locally", id)))?;

            cnac.get_static_auxiliary_hyper_ratchet()
                .verify_level(Some(sess_sec_settings.security_level))
                .map(|_| ())
                .map_err(|_| NetworkError::InvalidRequest("The security level is too high"))?;
        }

        Ok(NodeRequest::ConnectToHypernode(authentication_request, connect_mode, fcm_keys, udp_mode, ka, sess_sec_settings))
    }
}

/// Convenience for building peer to peer registration requests
pub struct PeerRegistrationBuilder;

impl PeerRegistrationBuilder {
    pub async fn build(self, local_user: impl Into<UserIdentifier>, peer: impl Into<UserIdentifier>, remote: &mut impl Remote) -> Result<NodeRequest, NetworkError> {
        let local_user = local_user.into();
        let local_user = remote.account_manager().find_cnac_by_identifier(local_user.clone()).await
            .map_err(|err| NetworkError::Generic(err.into_string()))?
            .ok_or_else(|| NetworkError::Generic(format!("User {:?} does not exist locally", local_user)))?;
        let local_username = local_user.get_username();

        let (remote_cid, username_opt) = match peer.into() {
            UserIdentifier::ID(peer_cid) => (peer_cid, None),
            UserIdentifier::Username(uname) => (0, Some(uname))
        };

        let peer_conn = PeerConnectionType::HyperLANPeerToHyperLANPeer(local_user.get_cid(), remote_cid);
        let peer_signal = PeerSignal::PostRegister(peer_conn, local_username, username_opt, None, None, FcmPostRegister::Disable);

        Ok(NodeRequest::PeerCommand(local_user.get_cid(), peer_signal))
    }
}

pub struct PeerConnectionBuilder {
    session_security_settings: Option<SessionSecuritySettings>,
    udp_mode: Option<UdpMode>
}

impl PeerConnectionBuilder {

    pub async fn build(self, local_user: impl Into<UserIdentifier>, peer: impl Into<UserIdentifier>, remote: &mut impl Remote) -> Result<NodeRequest, NetworkError> {
        let local_user = local_user.into();
        let peer = peer.into();
        let sess_security_settings = self.session_security_settings.unwrap_or_default();
        let udp_mode = self.udp_mode.unwrap_or_default();

        let local_cid = remote.account_manager().find_local_user_information(local_user.clone()).await
            .map_err(|err| NetworkError::Generic(err.into_string()))?
            .ok_or_else(|| NetworkError::Generic(format!("User {:?} does not exist locally", local_user)))?;

        let (peer_cid, _) = remote.account_manager().find_target_information(local_user.clone(), peer.clone()).await
            .map_err(|err| NetworkError::Generic(err.into_string()))?
            .ok_or_else(|| NetworkError::Generic(format!("Peer {:?} is not registered to {:?} locally", local_user, peer)))?;

        let peer_conn = PeerConnectionType::HyperLANPeerToHyperLANPeer(local_cid, peer_cid);
        let peer_signal = PeerSignal::PostConnect(peer_conn, None, None, sess_security_settings, udp_mode);

        Ok(NodeRequest::PeerCommand(local_cid, peer_signal))
    }
}