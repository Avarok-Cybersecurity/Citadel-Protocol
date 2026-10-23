//! The STUN servers a node uses to learn its NAT mapping: required configuration.
//!
//! There is no built-in list. Every node is given its own, explicitly, through
//! [`StunServers::new`] (the SDK's `NodeBuilder::with_stun_servers`), and a node without one
//! refuses to start. NAT classification compares the external address each of three servers
//! reports, so a list needs at least [`MIN_STUN_SERVERS`] distinct `host:port` endpoints.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

/// The fewest distinct servers a list may name: NAT classification needs three observations.
pub const MIN_STUN_SERVERS: usize = 3;

const MAX_DNS_NAME_LEN: usize = 253;
const MAX_DNS_LABEL_LEN: usize = 63;

/// A validated list of at least [`MIN_STUN_SERVERS`] distinct `host:port` STUN endpoints, in
/// the order given. Cheap to clone.
#[derive(Clone, PartialEq, Eq)]
pub struct StunServers(Arc<[String]>);

/// Why a STUN server list was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StunServersError {
    /// No list was configured. There is no default.
    Missing,
    /// An entry is not a `host:port` endpoint (a DNS name, an IPv4 address or a bracketed IPv6
    /// address, and a non-zero port; no scheme, path or whitespace).
    Unparseable { entry: String, reason: &'static str },
    /// The same endpoint is named twice (host names compare case-insensitively).
    Duplicate { entry: String },
    /// Fewer than [`MIN_STUN_SERVERS`] endpoints.
    TooFew { distinct: usize },
}

impl fmt::Display for StunServersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(
                f,
                "STUN servers are required configuration: supply at least {MIN_STUN_SERVERS} distinct host:port endpoints (there is no default list)"
            ),
            Self::Unparseable { entry, reason } => {
                write!(f, "STUN server {entry:?} is not a host:port endpoint: {reason}")
            }
            Self::Duplicate { entry } => write!(f, "STUN server {entry:?} is listed twice"),
            Self::TooFew { distinct } => write!(
                f,
                "at least {MIN_STUN_SERVERS} distinct STUN servers are required, got {distinct}"
            ),
        }
    }
}

impl std::error::Error for StunServersError {}

impl StunServers {
    /// Validates `servers`: each must be a `host:port` endpoint, none may repeat, and there must
    /// be at least [`MIN_STUN_SERVERS`].
    pub fn new<V: Into<String>, I: IntoIterator<Item = V>>(
        servers: I,
    ) -> Result<Self, StunServersError> {
        let servers: Vec<String> = servers.into_iter().map(Into::into).collect();
        let mut seen: Vec<Endpoint> = Vec::with_capacity(servers.len());
        for entry in &servers {
            let endpoint = parse(entry).map_err(|reason| StunServersError::Unparseable {
                entry: entry.clone(),
                reason,
            })?;
            if seen.contains(&endpoint) {
                return Err(StunServersError::Duplicate {
                    entry: entry.clone(),
                });
            }
            seen.push(endpoint);
        }
        if seen.len() < MIN_STUN_SERVERS {
            return Err(StunServersError::TooFew {
                distinct: seen.len(),
            });
        }
        Ok(Self(servers.into()))
    }

    /// [`Self::new`] for a list that may not have been configured at all.
    pub fn required(servers: Option<Vec<String>>) -> Result<Self, StunServersError> {
        Self::new(servers.ok_or(StunServersError::Missing)?)
    }

    /// The endpoints, in the order given.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

/// A comma-separated list, as an operator writes it in an environment variable or a flag:
/// `"stun1.example.com:3478,stun2.example.com:3478,198.51.100.7:3478"`. Entries are not trimmed.
impl std::str::FromStr for StunServers {
    type Err = StunServersError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        if spec.is_empty() {
            return Err(StunServersError::Missing);
        }
        Self::new(spec.split(','))
    }
}

impl From<StunServers> for Vec<String> {
    fn from(servers: StunServers) -> Self {
        servers.0.to_vec()
    }
}

impl fmt::Debug for StunServers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// An endpoint as compared for duplicates.
#[derive(PartialEq, Eq)]
enum Endpoint {
    Ip(SocketAddr),
    Name(String, u16),
}

fn parse(entry: &str) -> Result<Endpoint, &'static str> {
    if let Ok(addr) = entry.parse::<SocketAddr>() {
        return if addr.port() == 0 {
            Err("the port must be non-zero")
        } else {
            Ok(Endpoint::Ip(addr))
        };
    }
    let (host, port) = entry.rsplit_once(':').ok_or("missing :port")?;
    let port: u16 = port
        .parse()
        .map_err(|_| "the port is not a number in 1..=65535")?;
    if port == 0 {
        return Err("the port must be non-zero");
    }
    if host.starts_with('[') || host.contains(':') {
        return Err("an IPv6 address must be bracketed, and no scheme may precede the host");
    }
    validate_dns_name(host)?;
    Ok(Endpoint::Name(host.to_ascii_lowercase(), port))
}

fn validate_dns_name(host: &str) -> Result<(), &'static str> {
    if host.is_empty() {
        return Err("the host is empty");
    }
    if host.len() > MAX_DNS_NAME_LEN {
        return Err("the host name is longer than 253 characters");
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > MAX_DNS_LABEL_LEN {
            return Err("a host name label is empty or longer than 63 characters");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("the host may contain only letters, digits, '-' and '.'");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("a host name label may not begin or end with '-'");
        }
    }
    Ok(())
}

/// Loopback endpoints nothing answers on, for tests: under `localhost-testing` no STUN server is
/// contacted, and without it identification fails over to local candidates.
#[cfg(test)]
pub(crate) fn unanswered_loopback() -> StunServers {
    StunServers::new(["127.0.0.1:3478", "127.0.0.1:3479", "127.0.0.1:3480"])
        .expect("three distinct loopback endpoints")
}

#[cfg(test)]
#[path = "stun_servers_tests.rs"]
mod tests;
