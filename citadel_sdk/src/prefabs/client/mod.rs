use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
use crate::prefabs::ClientServerRemote;
use crate::prelude::*;
use std::net::{SocketAddr, ToSocketAddrs};
use uuid::Uuid;

/// A kernel that assists in creating and/or connecting to a group
pub mod broadcast;
/// A kernel that assists in allowing multiple possible peer-to-peer connections
pub mod peer_connection;
/// A kernel that only makes a single client-to-server connection
pub mod single_connection;

#[async_trait]
pub trait PrefabFunctions<'a, Arg: Send + 'a>: Sized + 'a {
    type UserLevelInputFunction: Send + 'a;
    /// Shared between the kernel and the on_c2s_channel_received function
    type SharedBundle: Send + 'a;

    fn get_shared_bundle(&self) -> Self::SharedBundle;

    async fn on_c2s_channel_received(
        connect_success: ConnectionSuccess,
        remote: ClientServerRemote,
        arg: Arg,
        fx: Self::UserLevelInputFunction,
        shared: Self::SharedBundle,
    ) -> Result<(), NetworkError>;

    fn construct(kernel: Box<dyn NetKernel + 'a>) -> Self;

    /// Creates a new connection with a central server entailed by the user information
    fn new(
        server_connection_settings: ServerConnectionSettings,
        arg: Arg,
        on_channel_received: Self::UserLevelInputFunction,
    ) -> Self {
        let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();
        let server_conn_kernel = SingleClientServerConnectionKernel::new(
            server_connection_settings,
            server_password,
            |connect_success, remote| {
                on_channel_received_fn::<_, Self>(
                    connect_success,
                    remote,
                    rx,
                    arg,
                    on_channel_received,
                )
            },
        );

        let this = Self::construct(Box::new(server_conn_kernel));
        assert!(tx.send(this.get_shared_bundle()).is_ok());
        this
    }
}

async fn on_channel_received_fn<'a, Arg: Send + 'a, T: PrefabFunctions<'a, Arg>>(
    connect_success: ConnectionSuccess,
    remote: ClientServerRemote,
    rx_bundle: citadel_io::tokio::sync::oneshot::Receiver<T::SharedBundle>,
    arg: Arg,
    on_channel_received: T::UserLevelInputFunction,
) -> Result<(), NetworkError> {
    let shared = rx_bundle
        .await
        .map_err(|err| NetworkError::Generic(err.to_string()))?;
    T::on_c2s_channel_received(connect_success, remote, arg, on_channel_received, shared).await
}

/// Used to instantiate a client to server connection
pub struct ServerConnectionSettingsBuilder<T: ToSocketAddrs = String> {
    password: Option<SecBuffer>,
    username: Option<String>,
    name: Option<String>,
    psk: Option<PreSharedKey>,
    address: Option<T>,
    udp_mode: Option<UdpMode>,
    session_security_settings: Option<SessionSecuritySettings>,
    authless_uuid: Option<Uuid>,
    is_connect: bool,
}

impl<T: ToSocketAddrs> ServerConnectionSettingsBuilder<T> {
    /// Creates a new connection to a central server that uses no credentialed authentication, only a secure channel
    pub fn no_credentials(addr: T, id: Uuid) -> Self {
        Self {
            password: None,
            username: None,
            udp_mode: None,
            session_security_settings: None,
            name: None,
            psk: None,
            authless_uuid: Some(id),
            address: Some(addr),
            is_connect: false,
        }
    }

    /// Creates a new connection to a central server that uses a username and password for authentication. This should be used directly when
    /// constructing a registration request. If you are logging in, use the `credentialed_login` function instead.
    pub fn credentialed_registration<U: Into<String>, N: Into<String>, P: Into<SecBuffer>>(
        addr: T,
        username: U,
        alias: N,
        password: P,
    ) -> Self {
        Self {
            password: Some(password.into()),
            username: Some(username.into()),
            name: Some(alias.into()),
            psk: None,
            authless_uuid: None,
            address: Some(addr),
            udp_mode: None,
            session_security_settings: None,
            is_connect: false,
        }
    }

    /// Creates a new connection to a central server that uses a username and password for authentication. This should be used for the login process
    pub fn credentialed_login<U: Into<String>, P: Into<SecBuffer>>(
        addr: T,
        username: U,
        password: P,
    ) -> Self {
        Self {
            password: Some(password.into()),
            username: Some(username.into()),
            name: None,
            psk: None,
            authless_uuid: None,
            address: Some(addr),
            udp_mode: None,
            session_security_settings: None,
            is_connect: true,
        }
    }

    /// Adds a pre-shared key to the client-to-server connection. If the server expects a PSK, this is necessary.
    pub fn with_session_password<V: Into<PreSharedKey>>(mut self, psk: V) -> Self {
        self.psk = Some(psk.into());
        self
    }

    /// Sets the UDP mode for the client-to-server connection
    pub fn with_udp_mode(mut self, mode: UdpMode) -> Self {
        self.udp_mode = Some(mode);
        self
    }

    /// Disables the UDP mode for the client-to-server connection. The default setting is Disabled
    pub fn disable_udp(self) -> Self {
        self.with_udp_mode(UdpMode::Disabled)
    }

    /// Adds a session security settings to the client-to-server connection. This is necessary for the server to know how to handle the connection.
    pub fn with_session_security_settings<V: Into<SessionSecuritySettings>>(
        mut self,
        settings: V,
    ) -> Self {
        self.session_security_settings = Some(settings.into());
        self
    }

    /// Builds the client-to-server connection settings
    pub fn build(self) -> Result<ServerConnectionSettings, NetworkError> {
        let server_addr = if let Some(addr) = self.address {
            let addr = addr
                .to_socket_addrs()
                .map_err(|err| NetworkError::Generic(err.to_string()))?
                .next()
                .ok_or(NetworkError::Generic("No address found".to_string()))?;
            Some(addr)
        } else {
            None
        };

        if let Some(uuid) = self.authless_uuid {
            Ok(ServerConnectionSettings::NoCredentials {
                server_addr: server_addr
                    .ok_or(NetworkError::Generic("No address found".to_string()))?,
                uuid,
                udp_mode: self.udp_mode.unwrap_or_default(),
                session_security_settings: self.session_security_settings.unwrap_or_default(),
                pre_shared_key: self.psk,
            })
        } else if self.is_connect {
            Ok(ServerConnectionSettings::CredentialedConnect {
                username: self
                    .username
                    .ok_or(NetworkError::Generic("No username found".to_string()))?,
                password: self
                    .password
                    .ok_or(NetworkError::Generic("No password found".to_string()))?,
                udp_mode: self.udp_mode.unwrap_or_default(),
                session_security_settings: self.session_security_settings.unwrap_or_default(),
                pre_shared_key: self.psk,
            })
        } else {
            Ok(ServerConnectionSettings::CredentialedRegister {
                address: server_addr
                    .ok_or(NetworkError::Generic("No address found".to_string()))?,
                username: self
                    .username
                    .ok_or(NetworkError::Generic("No username found".to_string()))?,
                alias: self
                    .name
                    .ok_or(NetworkError::Generic("No alias found".to_string()))?,
                password: self
                    .password
                    .ok_or(NetworkError::Generic("No password found".to_string()))?,
                pre_shared_key: self.psk,
                udp_mode: self.udp_mode.unwrap_or_default(),
                session_security_settings: self.session_security_settings.unwrap_or_default(),
            })
        }
    }
}

/// The settings for a client-to-server connection
pub enum ServerConnectionSettings {
    NoCredentials {
        server_addr: SocketAddr,
        uuid: Uuid,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
        pre_shared_key: Option<PreSharedKey>,
    },
    CredentialedConnect {
        username: String,
        password: SecBuffer,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
        pre_shared_key: Option<PreSharedKey>,
    },
    CredentialedRegister {
        address: SocketAddr,
        username: String,
        alias: String,
        password: SecBuffer,
        pre_shared_key: Option<PreSharedKey>,
        udp_mode: UdpMode,
        session_security_settings: SessionSecuritySettings,
    },
}

impl ServerConnectionSettings {
    pub(crate) fn udp_mode(&self) -> UdpMode {
        match self {
            Self::NoCredentials { udp_mode, .. } => *udp_mode,
            Self::CredentialedRegister { udp_mode, .. } => *udp_mode,
            Self::CredentialedConnect { udp_mode, .. } => *udp_mode,
        }
    }

    pub(crate) fn session_security_settings(&self) -> SessionSecuritySettings {
        match self {
            Self::NoCredentials {
                session_security_settings,
                ..
            } => *session_security_settings,
            Self::CredentialedRegister {
                session_security_settings,
                ..
            } => *session_security_settings,
            Self::CredentialedConnect {
                session_security_settings,
                ..
            } => *session_security_settings,
        }
    }

    pub(crate) fn pre_shared_key(&self) -> Option<&PreSharedKey> {
        match self {
            Self::NoCredentials { pre_shared_key, .. } => pre_shared_key.as_ref(),
            Self::CredentialedRegister { pre_shared_key, .. } => pre_shared_key.as_ref(),
            Self::CredentialedConnect { pre_shared_key, .. } => pre_shared_key.as_ref(),
        }
    }
}
