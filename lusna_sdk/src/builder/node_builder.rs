use hyxe_net::prelude::*;

use futures::Future;
use hyxe_net::re_imports::RustlsClientConfig;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Default)]
/// Used to construct a running client/peer or server instance
pub struct NodeBuilder {
    hypernode_type: Option<NodeType>,
    underlying_protocol: Option<UnderlyingProtocol>,
    backend_type: Option<BackendType>,
    server_argon_settings: Option<ArgonDefaultServerSettings>,
    services: Option<ServicesConfig>,
    server_misc_settings: Option<ServerMiscSettings>,
    client_tls_config: Option<RustlsClientConfig>,
    kernel_executor_settings: Option<KernelExecutorSettings>,
}

/// An awaitable future whose return value propagates any internal protocol or kernel-level errors
pub struct NodeFuture<'a, K> {
    inner: Pin<Box<dyn Future<Output = Result<K, NetworkError>> + 'a>>,
    _pd: PhantomData<fn() -> K>,
}

#[cfg(feature = "localhost-testing")]
unsafe impl<K> Send for NodeFuture<'_, K> {}

impl<K> Debug for NodeFuture<'_, K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeFuture")
    }
}

impl<K> Future for NodeFuture<'_, K> {
    type Output = Result<K, NetworkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

#[derive(Debug)]
/// Returned when an error occurs while building the node
pub enum NodeBuilderError {
    /// Denotes that the supplied configuration was invalid
    InvalidConfiguration(&'static str),
    /// Denotes any other error during the building process
    Other(String),
}

impl<T: ToString> From<T> for NodeBuilderError {
    fn from(err: T) -> Self {
        NodeBuilderError::Other(err.to_string())
    }
}

impl NodeBuilder {
    /// Returns a future that represents the both the protocol and kernel execution
    pub fn build<'a, 'b: 'a, K: NetKernel + 'b>(
        &'a mut self,
        kernel: K,
    ) -> Result<NodeFuture<'b, K>, NodeBuilderError> {
        self.check()?;
        let hypernode_type = self.hypernode_type.take().unwrap_or_default();
        let backend_type = self.backend_type.take().unwrap_or_else(|| {
            if cfg!(feature = "filesystem") {
                // set the home dir for fs type to the home directory
                let mut home_dir = dirs2::home_dir().unwrap();
                home_dir.push(format!(".lusna/{}", uuid::Uuid::new_v4().as_u128()));
                return BackendType::Filesystem(home_dir.to_str().unwrap().to_string());
            }

            BackendType::InMemory
        });
        let server_argon_settings = self.server_argon_settings.take();
        let server_services_cfg = self.services.take();
        let server_misc_settings = self.server_misc_settings.take();
        let client_config = self.client_tls_config.take().map(Arc::new);
        let kernel_executor_settings = self.kernel_executor_settings.take().unwrap_or_default();

        let underlying_proto = if let Some(proto) = self.underlying_protocol.take() {
            proto
        } else {
            // default to TLS self-signed to enforce hybrid cryptography
            UnderlyingProtocol::new_tls_self_signed()
                .map_err(|err| NodeBuilderError::Other(err.into_string()))?
        };

        Ok(NodeFuture {
            _pd: Default::default(),
            inner: Box::pin(async move {
                log::trace!(target: "lusna", "[NodeBuilder] Checking Tokio runtime ...");
                let rt = tokio::runtime::Handle::try_current()
                    .map_err(|err| NetworkError::Generic(err.to_string()))?;
                log::trace!(target: "lusna", "[NodeBuilder] Creating account manager ...");
                let account_manager = AccountManager::new(
                    backend_type,
                    server_argon_settings,
                    server_services_cfg,
                    server_misc_settings,
                )
                .await?;
                log::trace!(target: "lusna", "[NodeBuilder] Creating KernelExecutor ...");
                let kernel_executor = KernelExecutor::new(
                    rt,
                    hypernode_type,
                    account_manager,
                    kernel,
                    underlying_proto,
                    client_config,
                    kernel_executor_settings,
                )
                .await?;
                log::trace!(target: "lusna", "[NodeBuilder] Executing kernel");
                kernel_executor.execute().await
            }),
        })
    }

    /// Defines the node type. By default, Peer is used. If a server is desired, a bind address is expected
    /// ```
    /// use std::net::SocketAddr;
    /// use std::str::FromStr;
    /// use lusna_sdk::prelude::NodeBuilder;
    /// use hyxe_net::prelude::NodeType;
    ///
    /// NodeBuilder::default().with_node_type(NodeType::Server(SocketAddr::from_str("0.0.0.0:25021").unwrap()));
    /// ```
    pub fn with_node_type(&mut self, node_type: NodeType) -> &mut Self {
        self.hypernode_type = Some(node_type);
        self
    }

    /// Sets the backend used to synchronize client account information. By default, uses the filesystem.
    /// When the enterprise feature is set, a SQL database (MySQL, PostgreSQL, SQLite) is available. Using a single SQL cluster can be used in combination with
    /// a cluster of load-balancing running ['NetKernel']'s on different IPs to construct scaled applications
    pub fn with_backend(&mut self, backend_type: BackendType) -> &mut Self {
        self.backend_type = Some(backend_type);
        self
    }

    /// Sets the desired settings for the [`KernelExecutor`]
    pub fn with_kernel_executor_settings(
        &mut self,
        kernel_executor_settings: KernelExecutorSettings,
    ) -> &mut Self {
        self.kernel_executor_settings = Some(kernel_executor_settings);
        self
    }

    /// Attaches custom Argon settings for password hashing at the server
    pub fn with_server_argon_settings(
        &mut self,
        settings: ArgonDefaultServerSettings,
    ) -> &mut Self {
        self.server_argon_settings = Some(settings);
        self
    }

    /// Attaches a google services json path, allowing the use of Google Auth and other dependent services like Realtime Database for android/IOS messaging. Required when using [`Self::with_google_realtime_database_config`]
    pub fn with_google_services_json_path<T: Into<String>>(&mut self, path: T) -> &mut Self {
        let cfg = self.get_or_create_services();
        cfg.google_services_json_path = Some(path.into());
        self
    }

    /// Attaches miscellaneous server settings (e.g., passwordless mode)
    pub fn with_server_misc_settings(&mut self, misc_settings: ServerMiscSettings) -> &mut Self {
        self.server_misc_settings = Some(misc_settings);
        self
    }

    /// Creates a Google Realtime Database configuration given the project URL and API Key. Requires the use of [`Self::with_google_services_json_path`] to allow minting of JsonWebTokens
    /// at the central server
    pub fn with_google_realtime_database_config<T: Into<String>, R: Into<String>>(
        &mut self,
        url: T,
        api_key: R,
    ) -> &mut Self {
        let cfg = self.get_or_create_services();
        cfg.google_rtdb = Some(RtdbConfig {
            url: url.into(),
            api_key: api_key.into(),
        });
        self
    }

    /// Sets the underlying protocol for the server
    /// Default: TLS transport w/ self-signed cert
    pub fn with_underlying_protocol(&mut self, proto: UnderlyingProtocol) -> &mut Self {
        self.underlying_protocol = Some(proto);
        self
    }

    fn get_or_create_services(&mut self) -> &mut ServicesConfig {
        if self.services.is_some() {
            self.services.as_mut().unwrap()
        } else {
            let cfg = ServicesConfig::default();
            self.services = Some(cfg);
            self.services.as_mut().unwrap()
        }
    }

    /// Loads the accepted cert chain stored by the local operating system
    /// If a custom set of certs is required, run [`Self::with_custom_certs`]
    /// This is the default if no [`RustlsClientConfig`] is specified
    pub async fn with_native_certs(&mut self) -> Result<&mut Self, NodeBuilderError> {
        let certs = hyxe_net::re_imports::load_native_certs_async().await?;
        self.client_tls_config = Some(hyxe_net::re_imports::cert_vec_to_secure_client_config(
            &certs,
        )?);
        Ok(self)
    }

    /// The client will skip unconditionally server certificate verification
    /// This is not recommended
    pub fn with_insecure_skip_cert_verification(&mut self) -> &mut Self {
        self.client_tls_config = Some(hyxe_net::re_imports::insecure::rustls_client_config());
        self
    }

    /// Loads a custom list of certs into the acceptable certificate list. Connections that present server certificates
    /// that are outside of this list during the handshake process are refused
    pub fn with_custom_certs<T: AsRef<[u8]>>(
        &mut self,
        custom_certs: &[T],
    ) -> Result<&mut Self, NodeBuilderError> {
        let cfg = hyxe_net::re_imports::create_rustls_client_config(custom_certs)?;
        self.client_tls_config = Some(cfg);
        Ok(self)
    }

    /// The file should be a DER formatted certificate
    pub async fn with_pem_file<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<&mut Self, NodeBuilderError> {
        let mut der = std::io::Cursor::new(tokio::fs::read(path).await?);
        let certs = hyxe_net::re_imports::rustls_pemfile::certs(&mut der)?;
        self.client_tls_config = Some(hyxe_net::re_imports::create_rustls_client_config(&certs)?);
        Ok(self)
    }

    fn check(&self) -> Result<(), NodeBuilderError> {
        if let Some(svc) = self.services.as_ref() {
            if svc.google_rtdb.is_some() && svc.google_services_json_path.is_none() {
                return Err(NodeBuilderError::InvalidConfiguration(
                    "Google realtime database is enabled, yet, a services path is not provided",
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::builder::node_builder::NodeBuilder;
    use crate::prefabs::server::empty::EmptyKernel;
    use crate::prelude::{BackendType, NodeType};
    use hyxe_net::prelude::{KernelExecutorSettings, UnderlyingProtocol};
    use rstest::rstest;
    use std::str::FromStr;

    #[test]
    fn okay_config() {
        let _ = NodeBuilder::default()
            .with_google_realtime_database_config("123", "456")
            .with_google_services_json_path("abc")
            .build(EmptyKernel::default())
            .unwrap();
    }

    #[test]
    fn bad_config() {
        assert!(NodeBuilder::default()
            .with_google_realtime_database_config("123", "456")
            .build(EmptyKernel::default())
            .is_err());
    }

    #[rstest]
    #[tokio::test]
    #[timeout(std::time::Duration::from_secs(60))]
    async fn test_options(
        #[values(UnderlyingProtocol::new_quic_self_signed(), UnderlyingProtocol::new_tls_self_signed().unwrap())]
        underlying_protocol: UnderlyingProtocol,
        #[values(NodeType::Peer, NodeType::Server(std::net::SocketAddr::from_str("127.0.0.1:9999").unwrap()))]
        node_type: NodeType,
        #[values(KernelExecutorSettings::default(), KernelExecutorSettings::default().with_max_concurrency(2))]
        kernel_settings: KernelExecutorSettings,
        #[values(BackendType::InMemory, BackendType::new("file:/hello_world/path/").unwrap())]
        backend_type: BackendType,
    ) {
        let mut builder = NodeBuilder::default();
        let _ = builder
            .with_underlying_protocol(underlying_protocol.clone())
            .with_backend(backend_type.clone())
            .with_node_type(node_type.clone())
            .with_kernel_executor_settings(kernel_settings.clone())
            .with_insecure_skip_cert_verification()
            .with_native_certs()
            .await
            .unwrap();

        assert!(builder.underlying_protocol.is_some());
        assert_eq!(backend_type, builder.backend_type.clone().unwrap());
        assert_eq!(node_type, builder.hypernode_type.clone().unwrap());
        assert_eq!(
            kernel_settings,
            builder.kernel_executor_settings.clone().unwrap()
        );

        let _ = builder.build(EmptyKernel::default()).unwrap();
    }
}
