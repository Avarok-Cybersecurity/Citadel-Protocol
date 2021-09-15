use crate::prelude::{NetKernel, UnderlyingProtocol, KernelExecutor};
use crate::re_imports::HyperNodeType;
use hyxe_user::account_manager::AccountManager;
use hyxe_user::backend::BackendType;
use hyxe_crypt::argon::argon_container::ArgonDefaultServerSettings;
use hyxe_user::external_services::{ServicesConfig, RtdbConfig};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use futures::Future;
use crate::error::NetworkError;
use std::net::SocketAddr;
use std::str::FromStr;
use std::task::{Context, Poll};

#[derive(Default)]
pub struct KernelBuilder {
    hypernode_type: Option<HyperNodeType>,
    home_directory: Option<String>,
    underlying_protocol: Option<UnderlyingProtocol>,
    backend_type: Option<BackendType>,
    server_argon_settings: Option<ArgonDefaultServerSettings>,
    services: Option<ServicesConfig>
}

pub struct KernelFuture {
    inner: Pin<Box<dyn Future<Output=Result<(), NetworkError>> + 'static>>
}

impl Future for KernelFuture {
    type Output = Result<(), NetworkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

pub struct ServerConfigBuilder<'a> {
    ptr: &'a mut KernelBuilder
}

impl Deref for ServerConfigBuilder<'_> {
    type Target = KernelBuilder;

    fn deref(&self) -> &Self::Target {
        &*self.ptr
    }
}

impl DerefMut for ServerConfigBuilder<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ptr
    }
}

#[derive(Debug)]
pub enum KernelBuilderError {
    InvalidConfiguration(&'static str),
    Other(String)
}

impl ServerConfigBuilder<'_> {
    pub fn with_server_argon_settings(&mut self, settings: ArgonDefaultServerSettings) -> &mut Self {
        self.ptr.server_argon_settings = Some(settings);
        self
    }

    /// Attach a google services json path, allowing the use of Google Auth and other dependent services like Realtime Database for android/IOS messaging
    pub fn with_google_services_json_path<T: Into<String>>(&mut self, path: T) -> &mut Self {
        let cfg = self.get_or_create_services();
        cfg.google_services_json_path = Some(path.into());
        self
    }

    pub fn with_google_realtime_database_config<T: Into<String>, R: Into<String>>(&mut self, url: T, api_key: R) -> &mut Self {
        let cfg = self.get_or_create_services();
        cfg.google_rtdb = Some(RtdbConfig { url: url.into(), api_key: api_key.into()});
        self
    }

    fn get_or_create_services(&mut self) -> &mut ServicesConfig {
        if self.ptr.services.is_some() {
            self.ptr.services.as_mut().unwrap()
        } else {
            let cfg = ServicesConfig::default();
            self.ptr.services = Some(cfg);
            self.ptr.services.as_mut().unwrap()
        }
    }
}

impl KernelBuilder {

    pub fn build<K: NetKernel>(&mut self, kernel: K) -> Result<KernelFuture, KernelBuilderError> {
        self.check()?;
        let hypernode_type = self.hypernode_type.take().unwrap_or_default();
        let home_dir = self.home_directory.take();
        let backend_type = self.backend_type.take().unwrap_or_default();
        let server_argon_settings = self.server_argon_settings.take();
        let server_services_cfg = self.services.take();

        let underlying_proto = if let Some(proto) = self.underlying_protocol.take() {
            proto
        } else {
            UnderlyingProtocol::new_tls_self_signed().map_err(|err| KernelBuilderError::Other(err.into_string()))?
        };

        Ok(KernelFuture {
            inner: Box::pin(async move {
                let account_manager = AccountManager::new(hypernode_type.bind_addr().unwrap_or_else(|| SocketAddr::from_str("127.0.0.1:25021").unwrap()), home_dir, backend_type, server_argon_settings, server_services_cfg).await?;
                let kernel_executor = KernelExecutor::new(tokio::runtime::Handle::try_current().map_err(|err| NetworkError::Generic(err.to_string()))?, hypernode_type, account_manager, kernel, underlying_proto).await?;
                kernel_executor.execute().await
            })
        })
    }

    /// Defines the node type. By default, Peer is used. If a server is desired, a bind address is expected
    /// ```
    /// use hyxe_net::prelude::sdk::kernel_builder::KernelBuilder;
    /// use hyxe_nat::hypernode_type::HyperNodeType;
    /// use std::net::SocketAddr;
    /// use std::str::FromStr;
    ///
    /// KernelBuilder::default().with_node_type(HyperNodeType::Server(SocketAddr::from_str("0.0.0.0:25021").unwrap()));
    /// ```
    pub fn with_node_type(&mut self, node_type: HyperNodeType) -> &mut Self {
        self.hypernode_type = Some(node_type);
        self
    }

    /// Sets a custom application home directory. This will be used to store all the critical files, and in the case of using a filesystem backend, is also where
    /// the client data and hashed credentials are saved
    pub fn with_home_directory<T: Into<String>>(&mut self, dir: T) -> &mut Self {
        self.home_directory = Some(dir.into());
        self
    }

    /// Enables access to server-only configuration options
    pub fn server_config(&mut self) -> ServerConfigBuilder {
        ServerConfigBuilder { ptr: self }
    }

    /// Sets the backend used to synchronize client account information. By default, uses the filesystem.
    /// When the enterprise feature is set, a SQL database (MySQL, PostgreSQL, SQLite) is available. Using a single SQL cluster can be used in combination with
    /// a cluster of load-balancing running ['NetKernel']'s on different IPs to construct wide applications
    pub fn with_backend(&mut self, backend_type: BackendType) -> &mut Self {
        self.backend_type = Some(backend_type);
        self
    }

    fn check(&self) -> Result<(), KernelBuilderError> {
        if let Some(svc) = self.services.as_ref() {
            if svc.google_rtdb.is_some() && svc.google_services_json_path.is_none() {
                return Err(KernelBuilderError::InvalidConfiguration("Google realtime database is enabled, yet, a services path is not provided"))
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::sdk::kernel_builder::KernelBuilder;
    use crate::sdk::prefabs::server::empty_kernel::EmptyKernel;

    #[test]
    fn okay_config() {
        let _ = KernelBuilder::default().server_config().with_google_realtime_database_config("123", "456").with_google_services_json_path("abc").build(EmptyKernel{}).unwrap();
    }

    #[test]
    fn bad_config() {
        assert!(KernelBuilder::default().server_config().with_google_realtime_database_config("123", "456").build(EmptyKernel{}).is_err());
    }
}