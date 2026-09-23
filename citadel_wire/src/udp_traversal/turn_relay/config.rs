//! TURN relay configuration supplied by the application for one P2P attempt.
//!
//! Nothing here has a default: the application passes every server, credential and policy
//! explicitly. Credentials are short-lived secrets (e.g. Cloudflare Realtime TURN mints them with a
//! TTL of at most 48 h); they never leave the node — they are not serializable and `Debug` redacts
//! them.

use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::time::SystemTime;

/// How the client reaches the TURN server. The relayed leg (TURN server ↔ peer) is always UDP.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum TurnTransport {
    Udp,
    Tcp,
    /// TLS over TCP (`turns:`), verified against the node's root store with SNI = the URL host.
    Tls,
}

/// A parsed RFC 7065 TURN URI: `turn:host[:port][?transport=udp|tcp]` or
/// `turns:host[:port][?transport=tcp]`.
///
/// A missing port takes the value RFC 7065 §3 assigns to the scheme (3478 for `turn:`, 5349 for
/// `turns:`), and a missing transport takes the one RFC 7065 assigns (UDP for `turn:`, TCP for
/// `turns:`). These are part of the URI grammar, not local defaults.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TurnUrl {
    pub host: String,
    pub port: u16,
    pub transport: TurnTransport,
}

const TURN_DEFAULT_PORT: u16 = 3478;
const TURNS_DEFAULT_PORT: u16 = 5349;

impl FromStr for TurnUrl {
    type Err = std::io::Error;

    fn from_str(url: &str) -> Result<Self, Self::Err> {
        let bad = |why: &str| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid TURN URL {url:?}: {why}"),
            )
        };
        let (secure, rest) = if let Some(rest) = url.strip_prefix("turns:") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("turn:") {
            (false, rest)
        } else {
            return Err(bad("scheme must be turn: or turns:"));
        };
        let (authority, query) = match rest.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (rest, None),
        };
        let transport_param = match query {
            None => None,
            Some(q) => match q.strip_prefix("transport=") {
                Some("udp") => Some(TurnTransport::Udp),
                Some("tcp") => Some(TurnTransport::Tcp),
                _ => return Err(bad("the only query supported is transport=udp|tcp")),
            },
        };
        let transport = match (secure, transport_param) {
            (false, None | Some(TurnTransport::Udp)) => TurnTransport::Udp,
            (false, Some(_)) => TurnTransport::Tcp,
            (true, None | Some(TurnTransport::Tcp)) => TurnTransport::Tls,
            (true, Some(_)) => return Err(bad("turns: requires transport=tcp (DTLS unsupported)")),
        };
        let (host, port) = split_host_port(authority).ok_or_else(|| bad("bad host[:port]"))?;
        let port = match port {
            Some(p) => p.parse::<u16>().map_err(|_| bad("bad port"))?,
            None if secure => TURNS_DEFAULT_PORT,
            None => TURN_DEFAULT_PORT,
        };
        if host.is_empty() {
            return Err(bad("empty host"));
        }
        Ok(Self {
            host: host.to_string(),
            port,
            transport,
        })
    }
}

fn split_host_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        return match after {
            "" => Some((host, None)),
            p => Some((host, Some(p.strip_prefix(':')?))),
        };
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Some((h, Some(p))),
        None => Some((authority, None)),
    }
}

/// One TURN server and the long-term credential used to authenticate against it.
#[derive(Clone)]
pub struct TurnServerCredential {
    pub url: TurnUrl,
    pub username: String,
    pub credential: String,
    /// When the credential stops being valid. `None` means the application asserts the
    /// credential does not expire (static coturn users); ephemeral providers must set it.
    pub expires_at: Option<SystemTime>,
}

impl TurnServerCredential {
    pub fn new(
        url: &str,
        username: impl Into<String>,
        credential: impl Into<String>,
        expires_at: Option<SystemTime>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            url: url.parse()?,
            username: username.into(),
            credential: credential.into(),
            expires_at,
        })
    }

    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        self.expires_at.is_some_and(|exp| exp <= now)
    }
}

impl Debug for TurnServerCredential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnServerCredential")
            .field("url", &self.url)
            .field("username", &"<redacted>")
            .field("credential", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// When the relay is used for a P2P attempt.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TurnPolicy {
    /// Try the direct (hole-punched) path first; relay only when the NAT pair is incompatible or
    /// the direct attempt fails.
    Fallback,
    /// Never attempt the direct path (the ICE "relay" transport policy): peers never learn each
    /// other's addresses from the hole punch. Both peers must use this policy.
    RelayOnly,
}

/// Everything the relay needs for one P2P attempt. Both peers must supply one; the lower-CID peer
/// allocates, the other dials the relayed address.
#[derive(Clone, Debug)]
pub struct TurnRelayConfig {
    /// Tried in order until one allocation succeeds. Expired credentials are skipped.
    pub servers: Vec<TurnServerCredential>,
    pub policy: TurnPolicy,
}

impl TurnRelayConfig {
    pub fn new(servers: Vec<TurnServerCredential>, policy: TurnPolicy) -> Self {
        Self { servers, policy }
    }

    /// Servers whose credentials are still valid at `now`, in configured order.
    pub fn usable_servers(&self, now: SystemTime) -> impl Iterator<Item = &TurnServerCredential> {
        self.servers.iter().filter(move |s| !s.is_expired_at(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn url(s: &str) -> TurnUrl {
        s.parse().unwrap()
    }

    #[test]
    fn parses_the_forms_cloudflare_returns() {
        assert_eq!(
            url("turn:turn.cloudflare.com:3478?transport=udp"),
            TurnUrl {
                host: "turn.cloudflare.com".into(),
                port: 3478,
                transport: TurnTransport::Udp
            }
        );
        assert_eq!(
            url("turn:turn.cloudflare.com:80?transport=tcp").transport,
            TurnTransport::Tcp
        );
        let tls = url("turns:turn.cloudflare.com:443?transport=tcp");
        assert_eq!((tls.port, tls.transport), (443, TurnTransport::Tls));
    }

    #[test]
    fn rfc7065_scheme_ports_and_transports() {
        assert_eq!(url("turn:example.org").port, 3478);
        assert_eq!(url("turn:example.org").transport, TurnTransport::Udp);
        assert_eq!(url("turns:example.org").port, 5349);
        assert_eq!(url("turns:example.org").transport, TurnTransport::Tls);
        let v6 = url("turn:[2001:db8::1]:3479?transport=tcp");
        assert_eq!((v6.host.as_str(), v6.port), ("2001:db8::1", 3479));
    }

    #[test]
    fn rejects_malformed_urls() {
        for bad in [
            "stun:example.org",
            "turn:",
            "turn:example.org:notaport",
            "turn:example.org?transport=sctp",
            "turns:example.org?transport=udp",
            "turn:[::1",
        ] {
            assert!(bad.parse::<TurnUrl>().is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn expired_credentials_are_not_usable_and_debug_redacts() {
        let now = SystemTime::now();
        let live = TurnServerCredential::new(
            "turn:a:1",
            "u",
            "secret-pass",
            Some(now + Duration::from_secs(60)),
        )
        .unwrap();
        let dead =
            TurnServerCredential::new("turn:b:1", "u", "p", Some(now - Duration::from_secs(1)))
                .unwrap();
        let forever = TurnServerCredential::new("turn:c:1", "u", "p", None).unwrap();
        let cfg = TurnRelayConfig::new(vec![live, dead, forever], TurnPolicy::Fallback);
        let hosts: Vec<_> = cfg
            .usable_servers(now)
            .map(|s| s.url.host.clone())
            .collect();
        assert_eq!(hosts, ["a", "c"]);
        assert!(!format!("{cfg:?}").contains("secret-pass"));
    }
}
