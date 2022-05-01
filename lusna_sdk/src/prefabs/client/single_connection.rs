use hyxe_net::prelude::*;
use parking_lot::Mutex;
use crate::remote_ext::ConnectSuccess;
use crate::prefabs::ClientServerRemote;
use crate::remote_ext::ProtocolRemoteExt;
use std::net::SocketAddr;
use futures::Future;
use std::marker::PhantomData;
use hyxe_net::auth::AuthenticationRequest;

/// A kernel that connects with the given credentials. If the credentials are not yet registered, then the [`Self::new_register`] function may be used, which will register the account before connecting.
/// This kernel will only allow outbound communication for the provided account
pub struct SingleClientServerConnectionKernel<F, Fut> {
    handler: Mutex<Option<F>>,
    udp_mode: UdpMode,
    auth_info: Mutex<Option<ConnectionType>>,
    session_security_settings: SessionSecuritySettings,
    remote: Option<NodeRemote>,
    // by using fn() -> Fut, the future does not need to be Sync
    _pd: PhantomData<fn() -> Fut>
}


#[derive(Debug)]
pub(crate) enum ConnectionType {
    Register { server_addr: SocketAddr, username: String, password: SecBuffer, full_name: String },
    Connect { username: String, password: SecBuffer },
    Passwordless { server_addr: SocketAddr }
}

impl<F, Fut> SingleClientServerConnectionKernel<F, Fut>
    where
        F: FnOnce(ConnectSuccess, ClientServerRemote) -> Fut + Send + 'static,
        Fut: Future<Output=Result<(), NetworkError>> + Send + 'static {
    /// Creates a new connection with a central server entailed by the user information
    pub fn new_connect<T: Into<String>, P: Into<SecBuffer>>(username: T, password: P, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: F) -> Self {

        Self {
            handler: Mutex::new(Some(on_channel_received)),
            udp_mode,
            auth_info: Mutex::new(Some(ConnectionType::Connect { username: username.into(), password: password.into() })),
            session_security_settings,
            remote: None,
            _pd: Default::default()
        }
    }

    /// Crates a new connection with a central server entailed by the user information and default configuration
    pub fn new_connect_defaults<T: Into<String>, P: Into<SecBuffer>>(username: T, password: P, on_channel_received: F) -> Self {
        Self::new_connect(username, password, Default::default(), Default::default(), on_channel_received)
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with custom parameters
    pub fn new_register<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(full_name: T, username: R, password: P, server_addr: SocketAddr, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: F) -> Self {

        Self {
            handler: Mutex::new(Some(on_channel_received)),
            udp_mode,
            auth_info: Mutex::new(Some(ConnectionType::Register {full_name: full_name.into(), server_addr, username: username.into(), password: password.into()})),
            session_security_settings,
            remote: None,
            _pd: Default::default()
        }
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with default parameters
    pub fn new_register_defaults<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(full_name: T, username: R, password: P, server_addr: SocketAddr, on_channel_received: F) -> Self {
        Self::new_register(full_name, username, password, server_addr, Default::default(), Default::default(), on_channel_received)
    }

    /// Creates a new authless connection with custom arguments
    pub fn new_passwordless(server_addr: SocketAddr, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: F) -> Self {
        Self {
            handler: Mutex::new(Some(on_channel_received)),
            udp_mode,
            auth_info: Mutex::new(Some(ConnectionType::Passwordless { server_addr })),
            session_security_settings,
            remote: None,
            _pd: Default::default()
        }
    }

    /// Creates a new authless connection with default arguments
    pub fn new_passwordless_defaults(server_addr: SocketAddr, on_channel_received: F) -> Self {
        Self::new_passwordless(server_addr, Default::default(), Default::default(), on_channel_received)
    }

}

#[async_trait]
impl<F, Fut> NetKernel for SingleClientServerConnectionKernel<F, Fut>
    where
        F: FnOnce(ConnectSuccess, ClientServerRemote) -> Fut + Send + 'static,
        Fut: Future<Output=Result<(), NetworkError>> + Send + 'static {

    fn load_remote(&mut self, server_remote: NodeRemote) -> Result<(), NetworkError> {
        self.remote = Some(server_remote);
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        let mut remote = self.remote.clone().unwrap();
        let (auth_info, handler) = {
            (self.auth_info.lock().take().unwrap(), self.handler.lock().take().unwrap())
        };

        let auth = match auth_info {
            ConnectionType::Register { full_name, server_addr, username, password } => {
                if !remote.account_manager().get_persistence_handler().username_exists(&username).await? {
                    let _reg_success = remote.register(server_addr, full_name.as_str(), username.as_str(), password.clone(), None, self.session_security_settings).await?;
                }

                AuthenticationRequest::credentialed(username, password)
            }

            ConnectionType::Connect { username, password } => {
                AuthenticationRequest::credentialed(username, password)
            }

            ConnectionType::Passwordless { server_addr } => {
                AuthenticationRequest::passwordless(server_addr)
            }
        };

        let connect_success = remote.connect(auth, Default::default(), None, self.udp_mode, None, self.session_security_settings).await?;
        let conn_type = VirtualTargetType::HyperLANPeerToHyperLANServer(connect_success.cid);

        (handler)(connect_success, ClientServerRemote { inner: remote, conn_type }).await
    }

    async fn on_node_event_received(&self, _message: HdpServerResult) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_stop(self) -> Result<(), NetworkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use std::sync::atomic::{AtomicBool, Ordering};
    use crate::test_common::server_info;

    #[tokio::test]
    async fn single_connection_registered() {
        crate::test_common::setup_log();

        static CLIENT_SUCCESS: AtomicBool = AtomicBool::new(false);
        let (server, server_addr) = server_info();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();

        let client_kernel = SingleClientServerConnectionKernel::new_register_defaults("Thomas P Braun", "nologik", "password", server_addr, |_channel,_remote| async move {
            log::info!("***CLIENT TEST SUCCESS***");
            CLIENT_SUCCESS.store(true, Ordering::Relaxed);
            stop_tx.send(()).unwrap();
            Ok(())
        });

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        tokio::select! {
            res0 = joined => { res0.unwrap(); },
            res1 = stop_rx => { res1.unwrap(); }
        }

        assert!(CLIENT_SUCCESS.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn single_connection_passwordless() {
        crate::test_common::setup_log();

        static CLIENT_SUCCESS: AtomicBool = AtomicBool::new(false);
        let (server, server_addr) = server_info();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();

        let client_kernel = SingleClientServerConnectionKernel::new_passwordless_defaults(server_addr, |_channel, _remote| async move {
            log::info!("***CLIENT TEST SUCCESS***");
            //_remote.inner.find_target("", "").await.unwrap().connect_to_peer().await.unwrap();
            CLIENT_SUCCESS.store(true, Ordering::Relaxed);
            stop_tx.send(()).unwrap();
            Ok(())
        });

        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        tokio::select! {
            res0 = joined => { res0.unwrap(); },
            res1 = stop_rx => { res1.unwrap(); }
        }

        assert!(CLIENT_SUCCESS.load(Ordering::Relaxed));
    }
}