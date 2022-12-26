use crate::error::NetworkError;
use crate::proto::misc::custom_io::{
    ChanneledClientConnection, ChanneledServerAcceptor, CustomClientIO, CustomServerAcceptor,
};
use crate::proto::node::TlsDomain;
use bytes::BytesMut;
use futures::Sink;
use hyxe_user::re_imports::__private::Formatter;
use hyxe_wire::exports::{Certificate, PrivateKey};
use hyxe_wire::tls::TLSQUICInterop;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::path::Path;
use tokio_stream::Stream;

#[derive(Clone)]
#[allow(variant_size_differences)]
pub enum UnderlyingProtocol {
    Tcp,
    Tls(TLSQUICInterop, TlsDomain, bool),
    Quic(Option<(Vec<Certificate>, PrivateKey)>, TlsDomain, bool),
    Custom(ChanneledServerAcceptor),
}

impl UnderlyingProtocol {
    pub fn custom(
        acceptor: tokio::sync::mpsc::UnboundedReceiver<ChanneledClientConnection>,
    ) -> UnderlyingProtocol {
        UnderlyingProtocol::Custom(CustomServerAcceptor { acceptor })
    }
    pub fn load_tls<P: AsRef<Path>, T: AsRef<str>, R: Into<String>>(
        path: P,
        password: T,
        domain: R,
    ) -> Result<Self, NetworkError> {
        let pkcs_12_der =
            std::fs::read(path).map_err(|err| NetworkError::Generic(err.to_string()))?;
        let interop = hyxe_wire::tls::create_server_config(&pkcs_12_der, password.as_ref())
            .map_err(|err| NetworkError::Generic(err.to_string()))?;
        Ok(Self::Tls(interop, Some(domain.into()), false))
    }

    pub fn load_quic<P: AsRef<Path>, T: AsRef<str>, R: Into<String>>(
        path: P,
        password: T,
        domain: R,
    ) -> Result<Self, NetworkError> {
        let (cert, priv_key) =
            hyxe_wire::misc::read_pkcs_12_der_to_quinn_keys(path, password.as_ref())
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
        let interop = hyxe_wire::tls::create_server_config(pkcs_12_der.as_ref(), password.as_ref())
            .map_err(|err| NetworkError::Generic(err.to_string()))?;
        Ok(Self::Tls(interop, Some(domain.into()), false))
    }

    pub fn load_quic_from_bytes<P: AsRef<[u8]>, T: AsRef<str>, R: Into<String>>(
        pkcs_12_der: P,
        password: T,
        domain: R,
    ) -> Result<Self, NetworkError> {
        let (cert, priv_key) =
            hyxe_wire::misc::pkcs12_to_quinn_keys(pkcs_12_der.as_ref(), password.as_ref())
                .map_err(|err| NetworkError::Generic(err.to_string()))?;
        Ok(Self::Quic(
            Some((cert, priv_key)),
            Some(domain.into()),
            false,
        ))
    }

    pub fn new_tls_self_signed() -> Result<Self, NetworkError> {
        let interop = hyxe_wire::tls::create_server_self_signed_config()
            .map_err(|err| NetworkError::Generic(err.to_string()))?;
        Ok(Self::Tls(interop, None, true))
    }

    /// The self-signed cert will be created internally automatically
    pub fn new_quic_self_signed() -> Self {
        Self::Quic(None, None, true)
    }

    /// Maps a TCP conn to a QUIC conn w/ no crypto
    /// Maps a TLS conn to a QUIC conn w
    #[allow(dead_code)]
    pub fn into_quic(self) -> Self {
        match self {
            Self::Quic(quic, tls_domain, is_self_signed) => {
                Self::Quic(quic, tls_domain, is_self_signed)
            }
            Self::Tcp => Self::new_quic_self_signed(),
            Self::Tls(interop, domain, is_self_signed) => Self::Quic(
                Some((interop.quic_chain, interop.quic_priv_key)),
                domain,
                is_self_signed,
            ),
            Self::Custom(..) => {
                panic!("Cannot map a custom acceptor into a QUIC node")
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn maybe_get_identity(&self) -> TlsDomain {
        match self {
            Self::Quic(_, domain, ..) => domain.clone(),
            Self::Tcp => None,
            Self::Tls(_, d, ..) => d.clone(),
            Self::Custom(..) => None,
        }
    }
}

impl Debug for UnderlyingProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            UnderlyingProtocol::Tcp => "TCP",
            UnderlyingProtocol::Tls(..) => "TLS",
            UnderlyingProtocol::Quic(..) => "QUIC",
            UnderlyingProtocol::Custom(..) => "Custom",
        };

        write!(f, "{}", label)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct P2PListenerConnectInfo {
    pub addr: SocketAddr,
    pub domain: TlsDomain,
}
