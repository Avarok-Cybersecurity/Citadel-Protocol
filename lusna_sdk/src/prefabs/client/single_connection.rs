use hyxe_net::prelude::*;
use parking_lot::Mutex;
use crate::remote_ext::ConnectSuccess;
use crate::prefabs::ShutdownRemote;
use crate::remote_ext::ProtocolRemoteExt;
use std::net::SocketAddr;
use futures::Future;
use std::marker::PhantomData;

/// A kernel that connects with the given credentials. If the credentials are not yet registered, then the [`Self::new_register`] function may be used, which will register the account before connecting.
/// This kernel will only allow outbound communication for the provided account
pub struct SingleClientServerConnectionKernel<F, Fut> {
    handler: Mutex<Option<Box<F>>>,
    username: String,
    udp_mode: UdpMode,
    register_info: Option<RegisterInfo>,
    session_security_settings: SessionSecuritySettings,
    password: Mutex<Option<SecBuffer>>,
    remote: Option<HdpServerRemote>,
    _pd: PhantomData<Fut>
}

struct RegisterInfo {
    server_addr: SocketAddr,
    full_name: String
}

impl<F, Fut> SingleClientServerConnectionKernel<F, Fut>
    where
        F: FnOnce(ConnectSuccess, ShutdownRemote) -> Fut + Send + 'static,
        Fut: Future<Output=Result<(), NetworkError>> + Send + Sync + 'static {
    /// Creates a new connection with a central server entailed by the user information
    pub fn new<T: Into<String>, P: Into<SecBuffer>>(username: T, password: P, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: F) -> Self {

        Self {
            handler: Mutex::new(Some(Box::new(on_channel_received))),
            username: username.into(),
            udp_mode,
            register_info: None,
            session_security_settings,
            password: Mutex::new(Some(password.into())),
            remote: None,
            _pd: Default::default()
        }
    }

    /// Crates a new connection with a central server entailed by the user information and default configuration
    pub fn new_defaults<T: Into<String>, P: Into<SecBuffer>>(username: T, password: P, on_channel_received: F) -> Self {
        Self::new(username, password, Default::default(), Default::default(), on_channel_received)
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with custom parameters
    pub fn new_register<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(full_name: T, username: R, password: P, server_addr: SocketAddr, udp_mode: UdpMode, session_security_settings: SessionSecuritySettings, on_channel_received: F) -> Self {

        Self {
            handler: Mutex::new(Some(Box::new(on_channel_received))),
            username: username.into(),
            udp_mode,
            register_info: Some(RegisterInfo { full_name: full_name.into(), server_addr }),
            session_security_settings,
            password: Mutex::new(Some(password.into())),
            remote: None,
            _pd: Default::default()
        }
    }

    /// First registers with a central server with the proposed credentials, and thereafter, establishes a connection with default parameters
    pub fn new_register_defaults<T: Into<String>, R: Into<String>, P: Into<SecBuffer>>(full_name: T, username: R, password: P, server_addr: SocketAddr, on_channel_received: F) -> Self {
        Self::new_register(full_name, username, password, server_addr, Default::default(), Default::default(), on_channel_received)
    }

}

#[async_trait]
impl<F, Fut> NetKernel for SingleClientServerConnectionKernel<F, Fut>
    where
        F: FnOnce(ConnectSuccess, ShutdownRemote) -> Fut + Send + 'static,
        Fut: Future<Output=Result<(), NetworkError>> + Send + Sync + 'static {

    fn load_remote(&mut self, server_remote: HdpServerRemote) -> Result<(), NetworkError> {
        self.remote = Some(server_remote);
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        let mut remote = self.remote.clone().unwrap();
        let (password, handler) = {
            (self.password.lock().take().unwrap(), self.handler.lock().take().unwrap())
        };

        if let Some(reg_info) = self.register_info.as_ref() {
            if !remote.account_manager().get_persistence_handler().username_exists(&self.username).await? {
                let _reg_success = remote.register(reg_info.server_addr, reg_info.full_name.as_str(), self.username.as_str(), password.clone(), None, self.session_security_settings).await?;
            }
        }

        let connect_success = remote.connect(&self.username, password, Default::default(), None, self.udp_mode, None, self.session_security_settings).await?;

        (handler)(connect_success, ShutdownRemote { inner: remote }).await
    }

    async fn on_server_message_received(&self, _message: HdpServerResult) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_stop(self) -> Result<(), NetworkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn single_connection() {
        crate::test_common::setup_log();

        static CLIENT_SUCCESS: AtomicBool = AtomicBool::new(false);
        let server_addr = SocketAddr::from_str("127.0.0.1:26000").unwrap();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();

        let client_kernel = SingleClientServerConnectionKernel::new_register_defaults("Thomas P Braun", "nologik", "password", server_addr, |_channel,_remote| async move {
            log::info!("***CLIENT TEST SUCCESS***");
            CLIENT_SUCCESS.store(true, Ordering::Relaxed);
            stop_tx.send(()).unwrap();
            Ok(())
        });

        let server = crate::test_common::default_server_test_node(server_addr);
        let client = NodeBuilder::default().build(client_kernel).unwrap();

        let joined = futures::future::try_join(server, client);

        tokio::select! {
            res0 = joined => { res0.unwrap(); },
            res1 = stop_rx => { res1.unwrap(); }
        }


        assert!(CLIENT_SUCCESS.load(Ordering::Relaxed));
    }
}