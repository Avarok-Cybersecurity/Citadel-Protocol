use crate::prelude::NetKernel;
use hyxe_crypt::prelude::SecBuffer;
use async_trait::async_trait;
use crate::hdp::hdp_server::HdpServerRemote;
use crate::error::NetworkError;
use crate::hdp::hdp_packet_processor::includes::HdpServerResult;
use crate::sdk::prefabs::ShutdownRemote;
use parking_lot::Mutex;
use crate::prelude::sdk::remote_ext::ConnectSuccess;

/// A kernel that assumes a user account already exists, and will login with the provided credentials. This will only allow outbound communication for the provided account
pub struct SingleClientServerConnectionKernel {
    handler: Mutex<Option<Box<dyn FnOnce(ConnectSuccess, ShutdownRemote) + Send + 'static>>>,
    username: String,
    password: Mutex<Option<SecBuffer>>,
    remote: Option<HdpServerRemote>
}

impl SingleClientServerConnectionKernel {
    pub fn new<T: Into<String>, P: Into<SecBuffer>, F>(username: T, password: P, on_channel_received: F) -> Self
        where F: FnOnce(ConnectSuccess, ShutdownRemote) + Send + 'static {

        Self {
            handler: Mutex::new(Some(Box::new(on_channel_received))),
            username: username.into(),
            password: Mutex::new(Some(password.into())),
            remote: None
        }
    }
}

#[async_trait]
impl NetKernel for SingleClientServerConnectionKernel {
    fn load_remote(&mut self, server_remote: HdpServerRemote) -> Result<(), NetworkError> {
        self.remote = Some(server_remote);
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        let mut remote = self.remote.clone().unwrap();
        let password = {
            self.password.lock().take().unwrap()
        };

        let connect_success = remote.connect_with_defaults(&self.username, password).await?;
        (self.handler.lock().take().unwrap())(connect_success, ShutdownRemote { inner: remote });

        Ok(())
    }

    async fn on_server_message_received(&self, _message: HdpServerResult) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_stop(self) -> Result<(), NetworkError> {
        Ok(())
    }
}