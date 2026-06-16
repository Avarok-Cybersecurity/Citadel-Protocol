use crate::error::NetworkError;
use crate::proto::misc::native_io::NativeIO;
use crate::proto::node::TlsDomain;
use citadel_io::{Mutex, ServerMode};
use citadel_wire::exports::{Certificate, PrivateKey};
use citadel_wire::tls::TLSQUICInterop;
use std::fmt::{self, Debug, Formatter};
use std::net::{TcpListener, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;

/// Config for ordered reliable transport without encryption (TCP).
pub struct NativeOrderedReliableConfig {
    pub listener: Option<Arc<Mutex<Option<citadel_io::tokio::net::TcpListener>>>>,
}

impl NativeOrderedReliableConfig {
    /// Creates an ordered reliable config with a random bind port.
    pub fn new() -> Self {
        Self { listener: None }
    }

    /// Creates config bound to a specific address.
    pub fn from_addr<T: ToSocketAddrs>(bind_addr: T) -> Result<Self, NetworkError> {
        let listener = citadel_wire::socket_helpers::get_tcp_listener(bind_addr)
            .map_err(|e| NetworkError::generic(e.to_string()))?;
        Self::from_tokio_listener(listener)
    }

    /// Creates config from a preset [`std::net::TcpListener`].
    pub fn from_std_listener(listener: TcpListener) -> Result<Self, NetworkError> {
        listener.set_nonblocking(true)?;
        Self::from_tokio_listener(citadel_io::tokio::net::TcpListener::from_std(listener)?)
    }

    /// Creates config from a preset tokio [`TcpListener`](citadel_io::tokio::net::TcpListener).
    pub fn from_tokio_listener(
        listener: citadel_io::tokio::net::TcpListener,
    ) -> Result<Self, NetworkError> {
        Ok(Self {
            listener: Some(Arc::new(Mutex::new(Some(listener)))),
        })
    }
}

impl Default for NativeOrderedReliableConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for NativeOrderedReliableConfig {
    fn clone(&self) -> Self {
        Self {
            listener: self.listener.clone(),
        }
    }
}

impl Debug for NativeOrderedReliableConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "OrderedReliable(TCP)")
    }
}

/// Config for ordered reliable secure transport (TLS).
pub struct NativeSecureConfig {
    pub interop: TLSQUICInterop,
    pub domain: TlsDomain,
    pub is_self_signed: bool,
}

impl NativeSecureConfig {
    /// Creates a self-signed TLS config.
    pub fn self_signed() -> Result<Self, NetworkError> {
        let interop = citadel_wire::tls::create_server_self_signed_config()
            .map_err(|err| NetworkError::generic(err.to_string()))?;
        Ok(Self {
            interop,
            domain: None,
            is_self_signed: true,
        })
    }

    /// Loads TLS config from a PKCS#12 file.
    pub fn from_pkcs12<P: AsRef<Path>, T: AsRef<str>, R: Into<String>>(
        path: P,
        password: T,
        domain: R,
    ) -> Result<Self, NetworkError> {
        let pkcs_12_der =
            std::fs::read(path).map_err(|err| NetworkError::generic(err.to_string()))?;
        Self::from_pkcs12_bytes(pkcs_12_der, password, domain)
    }

    /// Loads TLS config from PKCS#12 bytes.
    pub fn from_pkcs12_bytes<P: AsRef<[u8]>, T: AsRef<str>, R: Into<String>>(
        pkcs_12_der: P,
        password: T,
        domain: R,
    ) -> Result<Self, NetworkError> {
        let interop =
            citadel_wire::tls::create_server_config(pkcs_12_der.as_ref(), password.as_ref())
                .map_err(|err| NetworkError::generic(err.to_string()))?;
        Ok(Self {
            interop,
            domain: Some(domain.into()),
            is_self_signed: false,
        })
    }
}

impl Clone for NativeSecureConfig {
    fn clone(&self) -> Self {
        Self {
            interop: self.interop.clone(),
            domain: self.domain.clone(),
            is_self_signed: self.is_self_signed,
        }
    }
}

impl Debug for NativeSecureConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "OrderedReliableSecure(TLS)")
    }
}

/// Config for P2P-capable transport (QUIC).
pub struct NativeP2PConfig {
    pub crypto: Option<(Vec<Certificate<'static>>, PrivateKey<'static>)>,
    pub domain: TlsDomain,
    pub is_self_signed: bool,
}

impl NativeP2PConfig {
    /// Creates a self-signed QUIC config.
    /// The self-signed cert will be created internally automatically.
    pub fn self_signed() -> Self {
        Self {
            crypto: None,
            domain: None,
            is_self_signed: true,
        }
    }

    /// Loads QUIC config from a PKCS#12 file.
    pub fn from_pkcs12<P: AsRef<Path>, T: AsRef<str>, R: Into<String>>(
        path: P,
        password: T,
        domain: R,
    ) -> Result<Self, NetworkError> {
        let (cert, priv_key) =
            citadel_wire::misc::read_pkcs_12_der_to_quinn_keys(path, password.as_ref())
                .map_err(|err| NetworkError::generic(err.to_string()))?;
        Ok(Self {
            crypto: Some((cert, priv_key)),
            domain: Some(domain.into()),
            is_self_signed: false,
        })
    }

    /// Loads QUIC config from PKCS#12 bytes.
    pub fn from_pkcs12_bytes<P: AsRef<[u8]>, T: AsRef<str>, R: Into<String>>(
        pkcs_12_der: P,
        password: T,
        domain: R,
    ) -> Result<Self, NetworkError> {
        let (cert, priv_key) =
            citadel_wire::misc::pkcs12_to_quinn_keys(pkcs_12_der.as_ref(), password.as_ref())
                .map_err(|err| NetworkError::generic(err.to_string()))?;
        Ok(Self {
            crypto: Some((cert, priv_key)),
            domain: Some(domain.into()),
            is_self_signed: false,
        })
    }
}

impl Clone for NativeP2PConfig {
    fn clone(&self) -> Self {
        Self {
            crypto: self
                .crypto
                .as_ref()
                .map(|(cert, key)| (cert.clone(), key.clone_key())),
            domain: self.domain.clone(),
            is_self_signed: self.is_self_signed,
        }
    }
}

impl Debug for NativeP2PConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "P2P(QUIC)")
    }
}

/// Extension trait for `ServerMode<NativeIO>` convenience methods.
pub trait NativeServerModeExt {
    /// Extract the identity domain from this config, if any.
    fn maybe_get_identity(&self) -> TlsDomain;
}

impl NativeServerModeExt for ServerMode<NativeIO> {
    fn maybe_get_identity(&self) -> TlsDomain {
        match self {
            Self::OrderedReliable(..) => None,
            Self::OrderedReliableSecure(c) => c.domain.clone(),
            Self::P2P(c) => c.domain.clone(),
        }
    }
}
