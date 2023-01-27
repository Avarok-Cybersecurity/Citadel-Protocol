use crate::error::NetworkError;
use crate::proto::node::TlsDomain;
use citadel_user::re_exports::__private::Formatter;
use citadel_wire::exports::{Certificate, PrivateKey};
use citadel_wire::tls::TLSQUICInterop;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Clone)]
#[allow(variant_size_differences)]
pub enum ServerUnderlyingProtocol {
    Tcp,
    Tls(TLSQUICInterop, TlsDomain, bool),
    Quic(Option<(Vec<Certificate>, PrivateKey)>, TlsDomain, bool),
}

impl ServerUnderlyingProtocol {
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
            Self::Tcp => None,
            Self::Tls(_, d, ..) => d.clone(),
        }
    }
}

impl Debug for ServerUnderlyingProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            ServerUnderlyingProtocol::Tcp => "TCP",
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
