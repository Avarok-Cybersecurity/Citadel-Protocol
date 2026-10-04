//! Moving live QUIC client endpoints to fresh sockets after the local network changes.
//!
//! A QUIC connection survives a change of the client's address: quinn's
//! [`Endpoint::rebind`](quinn::Endpoint::rebind) swaps the endpoint's socket, every connection on
//! it sends from the new one and probes the path, and a server that allows migration (ours does,
//! see [`crate::quic`]) follows the client to its new address with no new handshake.
//!
//! Only the *client* of a QUIC connection can migrate, so only client-role endpoints are tracked.
//! A listener moved to a new address would be ignored by its peers, and an endpoint that sends
//! through this node's own TURN allocation must stay on it, so neither belongs here.
//!
//! This is local only: nothing new crosses the wire, so no protocol version gates it.

use std::net::SocketAddr;

/// One endpoint moved from `from` to `to`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rebound {
    pub from: SocketAddr,
    pub to: SocketAddr,
}

/// One endpoint that could not be moved. It keeps its old socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebindFailure {
    /// The endpoint's address before the attempt, if it could still be read.
    pub local: Option<SocketAddr>,
    pub error: String,
}

/// What a rebind did to each live endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebindReport {
    pub rebound: Vec<Rebound>,
    pub failed: Vec<RebindFailure>,
}

impl RebindReport {
    /// A report of no endpoints.
    pub fn empty() -> Self {
        Self {
            rebound: Vec::new(),
            failed: Vec::new(),
        }
    }

    /// Whether every live endpoint moved.
    pub fn is_complete(&self) -> bool {
        self.failed.is_empty()
    }
}

#[cfg(not(target_family = "wasm"))]
pub use native::LiveQuicEndpoints;

#[cfg(not(target_family = "wasm"))]
mod native {
    use super::{RebindFailure, RebindReport, Rebound};
    use crate::socket_helpers::get_udp_socket;
    use quinn::Endpoint;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    /// The client-role QUIC endpoints a node holds open. Cloning shares the set.
    ///
    /// An endpoint is dropped from the set once it has no open connections, when the set is
    /// next read ([`Self::track`], [`Self::len`], [`Self::rebind_all`]); until then it keeps
    /// its socket bound.
    #[derive(Clone)]
    pub struct LiveQuicEndpoints {
        endpoints: Arc<citadel_io::Mutex<Vec<Endpoint>>>,
    }

    impl LiveQuicEndpoints {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self {
                endpoints: Arc::new(citadel_io::Mutex::new(Vec::new())),
            }
        }

        /// Tracks a client endpoint whose connection is established. One tracked with no open
        /// connection is dropped at the next read.
        pub fn track(&self, endpoint: Endpoint) {
            let mut endpoints = self.endpoints.lock();
            prune(&mut endpoints);
            endpoints.push(endpoint);
        }

        /// How many tracked endpoints still have an open connection.
        pub fn len(&self) -> usize {
            let mut endpoints = self.endpoints.lock();
            prune(&mut endpoints);
            endpoints.len()
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// Moves every tracked endpoint with an open connection to a fresh socket on the
        /// unspecified address of its family, so the OS picks the current local address.
        pub fn rebind_all(&self) -> RebindReport {
            let endpoints = {
                let mut endpoints = self.endpoints.lock();
                prune(&mut endpoints);
                endpoints.clone()
            };
            let mut report = RebindReport::empty();
            for endpoint in &endpoints {
                match rebind(endpoint) {
                    Ok(moved) => report.rebound.push(moved),
                    Err(failure) => report.failed.push(failure),
                }
            }
            report
        }
    }

    fn prune(endpoints: &mut Vec<Endpoint>) {
        endpoints.retain(|endpoint| endpoint.open_connections() > 0);
    }

    fn rebind(endpoint: &Endpoint) -> Result<Rebound, RebindFailure> {
        let failed = |local: Option<SocketAddr>, error: String| RebindFailure { local, error };
        let from = endpoint
            .local_addr()
            .map_err(|err| failed(None, err.to_string()))?;
        let fresh = get_udp_socket(SocketAddr::new(unspecified_like(from.ip()), 0))
            .and_then(|socket| Ok(socket.into_std()?))
            .map_err(|err| failed(Some(from), err.to_string()))?;
        let to = fresh
            .local_addr()
            .map_err(|err| failed(Some(from), err.to_string()))?;
        endpoint
            .rebind(fresh)
            .map_err(|err| failed(Some(from), err.to_string()))?;
        log::info!(target: "citadel", "Rebound QUIC endpoint {from} -> {to}");
        Ok(Rebound { from, to })
    }

    fn unspecified_like(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
}
