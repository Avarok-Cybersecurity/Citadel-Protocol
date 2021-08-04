use native_tls::Identity;

use crate::hdp::hdp_server::TlsDomain;
use hyxe_nat::exports::{CertificateChain, PrivateKey};
use std::path::Path;
use crate::error::NetworkError;
use std::net::SocketAddr;

#[derive(Clone)]
#[allow(variant_size_differences)]
pub enum UnderlyingProtocol {
    Tcp,
    Tls(Identity, CertificateChain, PrivateKey, TlsDomain),
    Quic(Option<(CertificateChain, PrivateKey, TlsDomain)>)
}

impl UnderlyingProtocol {
    pub fn load_tls<P: AsRef<Path>, T: AsRef<str>>(path: P, password: T, domain: TlsDomain) -> Result<Self, NetworkError> {
        let (ident, cert, priv_key) = crate::hdp::misc::net::TlsListener::load_tls_pkcs(path, password)?;
        Ok(Self::Tls(ident, cert, priv_key, domain))
    }
    /// Maps a TCP conn to a QUIC conn w/ no crypto
    /// Maps a TLS conn to a QUIC conn w
    pub(crate) fn into_quic(self) -> Self {
        match self {
            Self::Quic(quic) => Self::Quic(quic),
            Self::Tcp => Self::Quic(None),
            Self::Tls(_, chain, priv_key, domain) => Self::Quic(Some((chain, priv_key, domain)))
        }
    }

    pub(crate) fn maybe_get_identity(&self) -> TlsDomain {
        match self {
            Self::Quic(res) => res.as_ref().map(|(_, _, d)| d.clone())?,
            Self::Tcp => None,
            Self::Tls(_, _, _, d) => d.clone()
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct P2PListenerConnectInfo {
    pub addr: SocketAddr,
    pub domain: TlsDomain
}