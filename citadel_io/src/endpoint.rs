//! A Citadel server identified by a WebSocket URL.
//!
//! A server behind an HTTP edge (a Cloudflare Worker, a reverse proxy) has no address of its own:
//! many servers share the edge's IPs and are told apart by hostname (TLS SNI, the `Host` header)
//! and path. A `SocketAddr` cannot carry either, so a client that must reach such a server dials
//! this URL instead.

use std::fmt;
use std::str::FromStr;

use url::{Host, Url};

use crate::NetworkError;

/// A `ws://` or `wss://` URL naming a Citadel server.
///
/// Parsing refuses anything a client could not dial as a WebSocket, and URLs carrying
/// credentials (`wss://user:pass@host/`): those would be sent to the edge as HTTP basic auth,
/// which is never what a Citadel client means.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WebSocketEndpoint {
    url: Url,
}

impl WebSocketEndpoint {
    /// Parses and validates a WebSocket URL.
    pub fn parse(input: &str) -> Result<Self, NetworkError> {
        let url = Url::parse(input)
            .map_err(|err| NetworkError::generic(format!("invalid endpoint {input:?}: {err}")))?;
        match url.scheme() {
            "ws" | "wss" => {}
            other => {
                return Err(NetworkError::generic(format!(
                    "endpoint {input:?} has scheme {other:?}; only ws and wss are dialable"
                )))
            }
        }
        if url.host().is_none() {
            return Err(NetworkError::generic(format!(
                "endpoint {input:?} has no host"
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(NetworkError::generic(format!(
                "endpoint {input:?} carries credentials; refusing to send them to the server's edge"
            )));
        }
        if url.fragment().is_some() {
            return Err(NetworkError::generic(format!(
                "endpoint {input:?} has a fragment, which a WebSocket URL cannot carry"
            )));
        }
        Ok(Self { url })
    }

    /// True for `wss://` (TLS to the edge).
    pub fn is_secure(&self) -> bool {
        self.url.scheme() == "wss"
    }

    /// The host to dial and to present as TLS SNI, without IPv6 brackets.
    pub fn host(&self) -> String {
        match self.url.host() {
            Some(Host::Domain(domain)) => domain.to_string(),
            Some(Host::Ipv4(ip)) => ip.to_string(),
            Some(Host::Ipv6(ip)) => ip.to_string(),
            None => unreachable!("parse() refuses an endpoint without a host"),
        }
    }

    /// The explicit port, or the scheme's default (80 for ws, 443 for wss).
    pub fn port(&self) -> u16 {
        self.url
            .port_or_known_default()
            .expect("ws and wss both have a known default port")
    }

    /// The URL as dialled.
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// Resolves the host to one socket address, for the protocol's per-connection bookkeeping.
    /// The dial itself resolves the hostname again, so a DNS change is honoured on reconnect.
    #[cfg(all(not(target_family = "wasm"), feature = "net"))]
    pub async fn resolve(&self) -> std::io::Result<std::net::SocketAddr> {
        let host = self.host();
        let port = self.port();
        let resolved = crate::tokio::net::lookup_host((host.as_str(), port))
            .await?
            .next();
        resolved.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{host}:{port} resolved to no addresses"),
            )
        })
    }
}

impl FromStr for WebSocketEndpoint {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for WebSocketEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.url.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::WebSocketEndpoint;

    #[test]
    fn wss_host_with_path_uses_the_default_port() {
        let ep = WebSocketEndpoint::parse("wss://acme.work.avarok.net/").unwrap();
        assert!(ep.is_secure());
        assert_eq!(ep.host(), "acme.work.avarok.net");
        assert_eq!(ep.port(), 443);
        assert_eq!(ep.as_str(), "wss://acme.work.avarok.net/");
    }

    #[test]
    fn ws_with_explicit_port_and_path() {
        let ep = WebSocketEndpoint::parse("ws://localhost:8787/acme").unwrap();
        assert!(!ep.is_secure());
        assert_eq!(ep.host(), "localhost");
        assert_eq!(ep.port(), 8787);
        assert_eq!(ep.as_str(), "ws://localhost:8787/acme");
    }

    #[test]
    fn ipv6_host_is_unbracketed() {
        let ep = WebSocketEndpoint::parse("ws://[::1]:9000/x").unwrap();
        assert_eq!(ep.host(), "::1");
        assert_eq!(ep.port(), 9000);
    }

    #[test]
    fn refuses_what_cannot_be_dialled_as_a_websocket() {
        for bad in [
            "https://acme.work.avarok.net/",
            "tcp://1.2.3.4:5",
            "acme.work.avarok.net",
            "ws://",
            "wss://user:pw@acme.work.avarok.net/",
            "wss://acme.work.avarok.net/#frag",
            "",
        ] {
            assert!(
                WebSocketEndpoint::parse(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }
}
