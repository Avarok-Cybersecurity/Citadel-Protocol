//! Underlying Protocol Implementation
//!
//! This module defines the low-level protocol implementation details for the Citadel Protocol.
//! It handles protocol negotiation, packet framing, and transport selection.
//!
//! # Features
//!
//! - Protocol negotiation
//! - Transport selection
//! - Packet framing
//! - Protocol versioning
//! - Error handling
//! - Security settings
//!
//! # Important Notes
//!
//! - Supports multiple transports
//! - Handles protocol upgrades
//! - Maintains backward compatibility
//! - Ensures secure defaults
//! - Validates protocol settings
//!
//! # Related Components
//!
//! - `net.rs`: Network operations
//! - `session_security_settings.rs`: Security configuration
//! - `session.rs`: Session management
//! - `node.rs`: Node implementation

use crate::error::NetworkError;
use crate::proto::node::TlsDomain;
use citadel_io::Mutex;
use citadel_user::re_exports::__private::Formatter;
use citadel_wire::exports::{Certificate, PrivateKey};
use citadel_wire::tls::TLSQUICInterop;
use std::fmt::Debug;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;

#[allow(variant_size_differences)]
pub enum ServerUnderlyingProtocol {
    Tcp(Option<Arc<Mutex<Option<citadel_io::tokio::net::TcpListener>>>>),
    Tls(TLSQUICInterop, TlsDomain, bool),
    Quic(
        Option<(Vec<Certificate<'static>>, PrivateKey<'static>)>,
        TlsDomain,
        bool,
    ),
}

impl Clone for ServerUnderlyingProtocol {
    fn clone(&self) -> Self {
        match self {
            Self::Tcp(listener) => Self::Tcp(listener.clone()),
            Self::Tls(interop, domain, self_signed) => {
                Self::Tls(interop.clone(), domain.clone(), *self_signed)
            }
            Self::Quic(keys, domain, self_signed) => Self::Quic(
                keys.as_ref()
                    .map(|(cert, key)| (cert.clone(), key.clone_key())),
                domain.clone(),
                *self_signed,
            ),
        }
    }
}

impl ServerUnderlyingProtocol {
    /// Creates a new [`ServerUnderlyingProtocol`] with a random bind port
    pub fn tcp() -> Self {
        Self::Tcp(None)
    }

    pub fn new_tcp<T: ToSocketAddrs>(bind_addr: T) -> Result<Self, NetworkError> {
        let listener = citadel_wire::socket_helpers::get_tcp_listener(bind_addr)?;
        Self::from_tokio_tcp_listener(listener)
    }

    /// Creates a new [`ServerUnderlyingProtocol`] with a preset [`std::net::TcpListener`]
    pub fn from_std_tcp_listener(listener: TcpListener) -> Result<Self, NetworkError> {
        listener.set_nonblocking(true)?;
        Self::from_tokio_tcp_listener(citadel_io::tokio::net::TcpListener::from_std(listener)?)
    }

    /// Creates a new [`ServerUnderlyingProtocol`] with a preset [`citadel_io::tokio::net::TcpListener`]
    pub fn from_tokio_tcp_listener(
        listener: citadel_io::tokio::net::TcpListener,
    ) -> Result<Self, NetworkError> {
        Ok(Self::Tcp(Some(Arc::new(Mutex::new(Some(listener))))))
    }

    pub fn load_tls<P: AsRef<Path>, T: AsRef<str>, R: Into<String>>(
        path: P,
        password: T,
        domain: R,
    ) -> Result<Self, NetworkError> {
        let pkcs_12_der =
            std::fs::read(path).map_err(|err| NetworkError::Generic(err.to_string()))?;
        Self::load_tls_from_bytes(pkcs_12_der, password, domain)
    }

    pub fn load_quic<P: AsRef<Path>, T: AsRef<str>, R: Into<String>>(
        path: P,
        password: T,
        domain: R,
    ) -> Result<Self, NetworkError> {
        let (cert, priv_key) =
            citadel_wire::misc::read_pkcs_12_der_to_quinn_keys(path, password.as_ref())
                .map_err(|err| NetworkError::Generic(err.to_string()))?;
        Ok(Self::Quic(
            Some((cert, priv_key)),
            Some(domain.into()),
            false,
        ))
    }

    pub fn load_tls_from_bytes<P: AsRef<[u8]>, T: AsRef<str>, R: Into<String>>(
        pkcs_12_der: P,
        password: T,
        domain: R,
    ) -> Result<Self, NetworkError> {
        let interop =
            citadel_wire::tls::create_server_config(pkcs_12_der.as_ref(), password.as_ref())
                .map_err(|err| NetworkError::Generic(err.to_string()))?;
        Ok(Self::Tls(interop, Some(domain.into()), false))
    }

    pub fn load_quic_from_bytes<P: AsRef<[u8]>, T: AsRef<str>, R: Into<String>>(
        pkcs_12_der: P,
        password: T,
        domain: R,
    ) -> Result<Self, NetworkError> {
        let (cert, priv_key) =
            citadel_wire::misc::pkcs12_to_quinn_keys(pkcs_12_der.as_ref(), password.as_ref())
                .map_err(|err| NetworkError::Generic(err.to_string()))?;
        Ok(Self::Quic(
            Some((cert, priv_key)),
            Some(domain.into()),
            false,
        ))
    }

    pub fn new_tls_self_signed() -> Result<Self, NetworkError> {
        let interop = citadel_wire::tls::create_server_self_signed_config()
            .map_err(|err| NetworkError::Generic(err.to_string()))?;
        Ok(Self::Tls(interop, None, true))
    }

    /// The self-signed cert will be created internally automatically
    pub fn new_quic_self_signed() -> Self {
        Self::Quic(None, None, true)
    }

    pub(crate) fn maybe_get_identity(&self) -> TlsDomain {
        match self {
            Self::Quic(_, domain, ..) => domain.clone(),
            Self::Tcp(..) => None,
            Self::Tls(_, d, ..) => d.clone(),
        }
    }
}

impl Debug for ServerUnderlyingProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            ServerUnderlyingProtocol::Tcp(..) => "TCP",
            ServerUnderlyingProtocol::Tls(..) => "TLS",
            ServerUnderlyingProtocol::Quic(..) => "QUIC",
        };

        write!(f, "{label}")
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct P2PListenerConnectInfo {
    pub addr: SocketAddr,
    pub domain: TlsDomain,
}
