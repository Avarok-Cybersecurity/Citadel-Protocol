//! Node Builder API for Citadel Protocol
//!
//! This module provides a builder pattern interface for constructing and configuring Citadel network nodes.
//! The builder supports creating both peer and server nodes with customizable settings for security,
//! networking, and backend storage.
//!
//! # Features
//! - Flexible node type configuration (Peer/Server)
//! - Multiple backend storage options (In-memory, Filesystem, SQL with enterprise feature)
//! - Customizable security settings (TLS, certificates)
//! - Google services integration (optional)
//! - STUN server configuration for NAT traversal
//! - Server authentication via pre-shared keys
//!
//! # Example
//! ```rust
//! use citadel_sdk::prelude::*;
//! use std::net::SocketAddr;
//! use std::str::FromStr;
//!
//! // Create a basic server node
//! let builder = DefaultNodeBuilder::default()
//!     .with_node_type(NodeType::Server(SocketAddr::from_str("0.0.0.0:25021").unwrap()))
//!     .with_backend(BackendType::InMemory);
//! ```
//!
//! # Important Notes
//! - Server nodes require a valid bind address
//! - Default backend is filesystem-based when the "filesystem" feature is enabled
//! - TLS is enabled by default with self-signed certificates
//! - When using Google services, both services JSON and database config must be set
//!
//! # Related Components
//! - [`NetKernel`]: Core networking kernel that processes node operations
//! - [`KernelExecutor`]: Executor for running the network kernel
//! - [`BackendType`]: Storage backend configurations

use citadel_proto::prelude::*;

use citadel_proto::kernel::KernelExecutorArguments;
use citadel_proto::macros::{ContextRequirements, LocalContextRequirements};
use citadel_proto::re_imports::RustlsClientConfig;
use citadel_types::crypto::HeaderObfuscatorSettings;
use futures::Future;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Used to construct a running client/peer or server instance
pub struct NodeBuilder<R: Ratchet = StackedRatchet> {
    hypernode_type: Option<NodeType>,
    underlying_protocol: Option<ServerUnderlyingProtocol>,
    backend_type: Option<BackendType>,
    server_argon_settings: Option<ArgonDefaultServerSettings>,
    #[cfg(feature = "google-services")]
    services: Option<ServicesConfig>,
    server_misc_settings: Option<ServerMiscSettings>,
    client_tls_config: Option<RustlsClientConfig>,
    kernel_executor_settings: Option<KernelExecutorSettings>,
    stun_servers: Option<Vec<String>>,
    local_only_server_settings: Option<ServerOnlySessionInitSettings>,
    _ratchet: PhantomData<R>,
}

/// Default node builder type
pub type DefaultNodeBuilder = NodeBuilder<StackedRatchet>;

pub type LightweightNodeBuilder = NodeBuilder<MonoRatchet>;

impl<R: Ratchet> Default for NodeBuilder<R> {
    fn default() -> Self {
        Self {
            hypernode_type: None,
            underlying_protocol: None,
            backend_type: None,
            server_argon_settings: None,
            #[cfg(feature = "google-services")]
            services: None,
            server_misc_settings: None,
            client_tls_config: None,
            kernel_executor_settings: None,
            stun_servers: None,
            local_only_server_settings: None,
            _ratchet: Default::default(),
        }
    }
}

/// An awaitable future whose return value propagates any internal protocol or kernel-level errors
pub struct NodeFuture<'a, K> {
    inner: Pin<Box<dyn FutureContextRequirements<'a, Result<K, NetworkError>>>>,
    _pd: PhantomData<fn() -> K>,
}

#[cfg(feature = "multi-threaded")]
trait FutureContextRequirements<'a, Output>:
    Future<Output = Output> + Send + LocalContextRequirements<'a>
{
}
#[cfg(feature = "multi-threaded")]
impl<'a, T: Future<Output = Output> + Send + LocalContextRequirements<'a>, Output>
    FutureContextRequirements<'a, Output> for T
{
}

#[cfg(not(feature = "multi-threaded"))]
trait FutureContextRequirements<'a, Output>:
    Future<Output = Output> + LocalContextRequirements<'a>
{
}
#[cfg(not(feature = "multi-threaded"))]
impl<'a, T: Future<Output = Output> + LocalContextRequirements<'a>, Output>
    crate::builder::node_builder::FutureContextRequirements<'a, Output> for T
{
}

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

impl<R: Ratchet + ContextRequirements> NodeBuilder<R> {
    /// Returns a future that represents the both the protocol and kernel execution
    pub fn build<'a, 'b: 'a, K: NetKernel<R> + 'b>(
        &'a mut self,
        kernel: K,
    ) -> anyhow::Result<NodeFuture<'b, K>> {
        self.check()?;
        let hypernode_type = self.hypernode_type.take().unwrap_or_default();
        let backend_type = self.backend_type.take().unwrap_or_else(|| {
            if cfg!(feature = "filesystem") {
                // set the home dir for fs type to the home directory
                let mut home_dir = dirs2::home_dir().unwrap();
                home_dir.push(format!(".citadel/{}", uuid::Uuid::new_v4().as_u128()));
                return BackendType::Filesystem(home_dir.to_str().unwrap().to_string());
            }

            BackendType::InMemory
        });
        let server_argon_settings = self.server_argon_settings.take();
        #[cfg(feature = "google-services")]
        let server_services_cfg = self.services.take();
        #[cfg(not(feature = "google-services"))]
        let server_services_cfg = None;
        let server_misc_settings = self.server_misc_settings.take();
        let client_config = self.client_tls_config.take().map(Arc::new);
        let kernel_executor_settings = self.kernel_executor_settings.take().unwrap_or_default();
        let stun_servers = self.stun_servers.take();

        let underlying_proto = if let Some(proto) = self.underlying_protocol.take() {
            proto
        } else {
            // default to TLS self-signed to enforce hybrid cryptography
            ServerUnderlyingProtocol::new_tls_self_signed()
                .map_err(|err| anyhow::Error::msg(err.into_string()))?
        };

        if matches!(underlying_proto, ServerUnderlyingProtocol::Tcp(..)) {
            citadel_logging::warn!(target: "citadel", "⚠️ WARNING ⚠️ TCP is discouraged for production use until The Citadel Protocol has been reviewed. Use TLS automatically by not changing the underlying protocol");
        }

        let server_only_session_init_settings = self.local_only_server_settings.take();

        Ok(NodeFuture {
            _pd: Default::default(),
            inner: Box::pin(async move {
                log::trace!(target: "citadel", "[NodeBuilder] Checking Tokio runtime ...");
                let rt = citadel_io::tokio::runtime::Handle::try_current()
                    .map_err(|err| NetworkError::Generic(err.to_string()))?;
                log::trace!(target: "citadel", "[NodeBuilder] Creating account manager ...");
                let account_manager = AccountManager::new(
                    backend_type,
                    server_argon_settings,
                    server_services_cfg,
                    server_misc_settings,
                )
                .await?;

                let args = KernelExecutorArguments {
                    rt,
                    hypernode_type,
                    account_manager,
                    kernel,
                    underlying_proto,
                    client_config,
                    kernel_executor_settings,
                    stun_servers,
                    server_only_session_init_settings,
                };

                log::trace!(target: "citadel", "[NodeBuilder] Creating KernelExecutor ...");
                let kernel_executor = KernelExecutor::<_, R>::new(args).await?;
                log::trace!(target: "citadel", "[NodeBuilder] Executing kernel");
                kernel_executor.execute().await
            }),
        })
    }

    /// Defines the node type. By default, Peer is used. If a server is desired, a bind address is expected
    /// ```
    /// use citadel_sdk::prelude::DefaultNodeBuilder;
    /// use citadel_proto::prelude::NodeType;
    ///
    /// DefaultNodeBuilder::default().with_node_type(NodeType::server("0.0.0.0:25021").unwrap());
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
    #[cfg(feature = "google-services")]
    pub fn with_google_services_json_path<T: Into<String>>(&mut self, path: T) -> &mut Self {
        let cfg = self.get_or_create_services();
        cfg.google_services_json_path = Some(path.into());
        self
    }

    /// Attaches miscellaneous server settings (e.g., transient mode, credential requirements)
    pub fn with_server_misc_settings(&mut self, misc_settings: ServerMiscSettings) -> &mut Self {
        self.server_misc_settings = Some(misc_settings);
        self
    }

    /// Creates a Google Realtime Database configuration given the project URL and API Key. Requires the use of [`Self::with_google_services_json_path`] to allow minting of JsonWebTokens
    /// at the central server
    #[cfg(feature = "google-services")]
    pub fn with_google_realtime_database_config<T: Into<String>, S: Into<String>>(
        &mut self,
        url: T,
        api_key: S,
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
    pub fn with_underlying_protocol(&mut self, proto: ServerUnderlyingProtocol) -> &mut Self {
        self.underlying_protocol = Some(proto);
        self
    }

    #[cfg(feature = "google-services")]
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
    pub async fn with_native_certs(&mut self) -> anyhow::Result<&mut Self> {
        let certs = citadel_proto::re_imports::load_native_certs_async().await?;
        self.client_tls_config = Some(citadel_proto::re_imports::cert_vec_to_secure_client_config(
            &certs,
        )?);
        Ok(self)
    }

    /// The client will skip unconditionally server certificate verification
    /// This is not recommended
    pub fn with_insecure_skip_cert_verification(&mut self) -> &mut Self {
        self.client_tls_config = Some(citadel_proto::re_imports::insecure::rustls_client_config());
        self
    }

    /// Loads a custom list of certs into the acceptable certificate list. Connections that present server certificates
    /// that are outside of this list during the handshake process are refused
    pub fn with_custom_certs<T: AsRef<[u8]>>(
        &mut self,
        custom_certs: &[T],
    ) -> anyhow::Result<&mut Self> {
        let cfg = citadel_proto::re_imports::create_rustls_client_config(custom_certs)?;
        self.client_tls_config = Some(cfg);
        Ok(self)
    }

    /// The file should be a DER formatted certificate
    #[cfg(feature = "std")]
    pub async fn with_pem_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<&mut Self> {
        let mut der = std::io::Cursor::new(citadel_io::tokio::fs::read(path).await?);
        let certs = citadel_proto::re_imports::rustls_pemfile::certs(&mut der).collect::<Vec<_>>();
        // iter certs and try collecting on the results
        let mut filtered_certs = Vec::new();
        for cert in certs {
            filtered_certs.push(cert?);
        }
        self.client_tls_config = Some(citadel_proto::re_imports::create_rustls_client_config(
            &filtered_certs,
        )?);
        Ok(self)
    }

    /// Specifies custom STUN servers. If left unspecified, will use the defaults (twilio and Google STUN servers)
    pub fn with_stun_servers<T: Into<String>, S: Into<Vec<T>>>(&mut self, servers: S) -> &mut Self {
        self.stun_servers = Some(servers.into().into_iter().map(|t| t.into()).collect());
        self
    }

    /// Sets the pre-shared key for the server. Only a server should set this value
    /// If no value is set, any client can connect to the server. If a pre-shared key
    /// is specified, the client must have the matching pre-shared key in order to
    /// register and connect with the server.
    pub fn with_server_password<T: Into<PreSharedKey>>(&mut self, password: T) -> &mut Self {
        let mut server_only_settings = self.local_only_server_settings.clone().unwrap_or_default();
        server_only_settings.declared_pre_shared_key = Some(password.into());
        self.local_only_server_settings = Some(server_only_settings);
        self
    }

    /// Sets the header obfuscator settings for the server
    pub fn with_server_declared_header_obfuscation<T: Into<HeaderObfuscatorSettings>>(
        &mut self,
        header_obfuscator_settings: T,
    ) -> &mut Self {
        let mut server_only_settings = self.local_only_server_settings.clone().unwrap_or_default();
        server_only_settings.declared_header_obfuscation_setting =
            header_obfuscator_settings.into();
        self.local_only_server_settings = Some(server_only_settings);
        self
    }

    fn check(&self) -> anyhow::Result<()> {
        #[cfg(feature = "google-services")]
        if let Some(svc) = self.services.as_ref() {
            if svc.google_rtdb.is_some() && svc.google_services_json_path.is_none() {
                return Err(anyhow::Error::msg(
                    "Google realtime database is enabled, yet, a services path is not provided",
                ));
            }
        }

        if let Some(stun_servers) = self.stun_servers.as_ref() {
            if stun_servers.len() != 3 {
                return Err(anyhow::Error::msg(
                    "There must be exactly 3 specified STUN servers",
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::builder::node_builder::DefaultNodeBuilder;
    use crate::prefabs::server::empty::EmptyKernel;
    use crate::prelude::{BackendType, NodeType};
    use citadel_io::tokio;
    use citadel_proto::prelude::{KernelExecutorSettings, ServerUnderlyingProtocol};
    use rstest::rstest;
    use std::str::FromStr;

    #[test]
    #[cfg(feature = "google-services")]
    fn okay_config() {
        let _ = DefaultNodeBuilder::default()
            .with_google_realtime_database_config("123", "456")
            .with_google_services_json_path("abc")
            .build(EmptyKernel::default())
            .unwrap();
    }

    #[test]
    #[cfg(feature = "google-services")]
    fn bad_config() {
        assert!(DefaultNodeBuilder::default()
            .with_google_realtime_database_config("123", "456")
            .build(EmptyKernel::default())
            .is_err());
    }

    #[test]
    fn bad_config2() {
        assert!(DefaultNodeBuilder::default()
            .with_stun_servers(["dummy1", "dummy2"])
            .build(EmptyKernel::default())
            .is_err());
    }

    #[rstest]
    #[tokio::test]
    #[timeout(std::time::Duration::from_secs(60))]
    #[allow(clippy::let_underscore_must_use)]
    async fn test_options(
        #[values(ServerUnderlyingProtocol::new_quic_self_signed(), ServerUnderlyingProtocol::new_tls_self_signed().unwrap()
        )]
        underlying_protocol: ServerUnderlyingProtocol,
        #[values(NodeType::Peer, NodeType::Server(std::net::SocketAddr::from_str("127.0.0.1:9999").unwrap()
        ))]
        node_type: NodeType,
        #[values(KernelExecutorSettings::default(), KernelExecutorSettings::default().with_max_concurrency(2)
        )]
        kernel_settings: KernelExecutorSettings,
        #[values(BackendType::InMemory, BackendType::new("file:/hello_world/path/").unwrap())]
        backend_type: BackendType,
    ) {
        let mut builder = DefaultNodeBuilder::default();
        let _ = builder
            .with_underlying_protocol(underlying_protocol.clone())
            .with_backend(backend_type.clone())
            .with_node_type(node_type)
            .with_kernel_executor_settings(kernel_settings.clone())
            .with_insecure_skip_cert_verification()
            .with_stun_servers(["dummy1", "dummy1", "dummy3"])
            .with_native_certs()
            .await
            .unwrap();

        assert!(builder.underlying_protocol.is_some());
        assert_eq!(backend_type, builder.backend_type.clone().unwrap());
        assert_eq!(node_type, builder.hypernode_type.unwrap());
        assert_eq!(
            kernel_settings,
            builder.kernel_executor_settings.clone().unwrap()
        );

        drop(builder.build(EmptyKernel::default()).unwrap());
    }
}
