//! # Async IP Resolution
//!
//! A lightweight, asynchronous client for obtaining global IPv4 and IPv6 addresses.
//! This crate provides reliable IP address resolution using multiple fallback services
//! and concurrent requests for improved reliability.
//!
//! ## Features
//!
//! - Async IP address resolution
//! - Support for both IPv4 and IPv6
//! - Multiple fallback services
//! - Concurrent resolution for improved reliability
//! - Internal IP address detection (native only; returns localhost on WASM)
//! - WebAssembly support
//! - Custom HTTP client support
//!
//! ## Usage
//!
//! ```rust,no_run
//! use async_ip::get_all;
//! use citadel_io::tokio;
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<(), async_ip::IpRetrieveError> {
//!     // Get both internal and external IP addresses
//!     use reqwest::Client;
//! let ip_info = get_all(None).await?;
//!     println!("External IPv6: {:?}", ip_info.external_ipv6);
//!     println!("Internal IPv4: {:?}", ip_info.internal_ip);
//!     Ok(())
//! }
//! ```
//!
//! ## Advanced Usage
//!
//! ```rust,no_run
//! use async_ip::{get_all_multi_concurrent, get_default_client};
//! use citadel_io::tokio;
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<(), async_ip::IpRetrieveError> {
//!     // Use multiple services concurrently with a custom client
//!     let client = get_default_client();
//!     let ip_info = get_all_multi_concurrent(Some(client)).await?;
//!     println!("External IPs: {:?}", ip_info);
//!     Ok(())
//! }
//! ```
//!
//! ## WebAssembly Support
//!
//! When compiled for WebAssembly, external IP detection works via HTTP services
//! (same as native). Internal IP detection returns localhost since browsers
//! cannot discover LAN IP addresses.
//!
//! ## Error Handling
//!
//! The crate uses a custom `IpRetrieveError` type that wraps various error
//! conditions that may occur during IP resolution, including network errors
//! and parsing failures.

#![deny(
    missing_docs,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    variant_size_differences,
    unused_features,
    unused_results
)]

use std::net::IpAddr;
use std::str::FromStr;

// use http since it's 2-3x faster
const URL_V6: &str = "http://api64.ipify.org";
//const URL_V4: &str = "http://api.ipify.org";

const URL_V6_1: &str = "http://ident.me";
//const URL_V4_1: &str = "http://v4.ident.me";

const URL_V6_2: &str = "http://v4v6.ipv6-test.com/api/myip.php";
//const URL_V4_2: &str = "http://v4.ipv6-test.com/api/myip.php";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// All the ip addr info for this node
pub struct IpAddressInfo {
    /// internal addr
    pub internal_ip: IpAddr,
    /// external v6 addr
    pub external_ipv6: Option<IpAddr>,
}

impl IpAddressInfo {
    /// Returns localhost addr
    pub fn localhost() -> Self {
        let localhost = IpAddr::from_str("127.0.0.1").unwrap();
        Self {
            internal_ip: localhost,
            external_ipv6: None,
        }
    }
}

/// Gets IP info concurrently using default multiple internal sources
pub async fn get_all_multi_concurrent(
    client: Option<reqwest::Client>,
) -> Result<IpAddressInfo, IpRetrieveError> {
    get_all_multi_concurrent_from(client, &[URL_V6, URL_V6_1, URL_V6_2]).await
}

/// Uses multiple url addrs to obtain the information
pub async fn get_all_multi_concurrent_from(
    client: Option<reqwest::Client>,
    v6_addrs: &[&str],
) -> Result<IpAddressInfo, IpRetrieveError> {
    let client = &client.unwrap_or_else(get_default_client);
    let internal_ip_future = resolve_internal_ip(false);
    let external_ipv6_future = futures::future::select_ok(
        v6_addrs
            .iter()
            .map(|addr| Box::pin(get_ip_from(Some(client.clone()), addr)))
            .collect::<Vec<_>>(),
    );

    let (res0, res2) = citadel_io::tokio::join!(internal_ip_future, external_ipv6_future);
    let internal_ip =
        res0.ok_or_else(|| citadel_io::error!(citadel_io::ErrorCode::IpInternalUnobtainable))?;
    let external_ipv6 = res2.ok().map(|r| r.0).and_then(only_ipv6);

    Ok(IpAddressInfo {
        internal_ip,
        external_ipv6,
    })
}

/// Returns all possible IPs for this node
pub async fn get_all(client: Option<reqwest::Client>) -> Result<IpAddressInfo, IpRetrieveError> {
    get_all_from(client, URL_V6).await
}

/// The "v6" endpoints answer over whatever transport reaches them, so on a host
/// with no IPv6 they reply over IPv4 with an IPv4 address. Storing that as
/// `external_ipv6` is not merely untidy: `citadel_wire`'s
/// `get_optimal_bind_socket` treats `external_ipv6.is_some()` on both peers as
/// "both nodes have an external IPv6 address" and binds `[::]:0`. The hole
/// puncher then advertises an IPv6 candidate on a host that has no IPv6
/// internal address to offer, and the peer cannot reach it.
fn only_ipv6(ip: IpAddr) -> Option<IpAddr> {
    ip.is_ipv6().then_some(ip)
}

/// Gets IP info concurrently using custom multiple internal sources
pub async fn get_all_from(
    client: Option<reqwest::Client>,
    v6_addr: &str,
) -> Result<IpAddressInfo, IpRetrieveError> {
    let client = client.unwrap_or_else(get_default_client);
    let internal_ip_future = resolve_internal_ip(false);
    let external_ipv6_future = get_ip_from(Some(client), v6_addr);
    let (res0, res2) = citadel_io::tokio::join!(internal_ip_future, external_ipv6_future);
    let internal_ip =
        res0.ok_or_else(|| citadel_io::error!(citadel_io::ErrorCode::IpInternalUnobtainable))?;
    let external_ipv6 = res2.ok().and_then(only_ipv6);

    Ok(IpAddressInfo {
        internal_ip,
        external_ipv6,
    })
}

/// Asynchronously gets the IP address of this node. If `prefer_ipv6` is true, then the client will
/// attempt to get the IP address; however, if the client is using an IPv4 address, that will be returned
/// instead.
///
/// If a reqwest client is supplied, this function will use that client to get the information. None by default.
pub async fn get_ip_from(
    client: Option<reqwest::Client>,
    addr: &str,
) -> Result<IpAddr, IpRetrieveError> {
    let client = client.unwrap_or_else(get_default_client);

    let resp = client
        .get(addr)
        .send()
        .await
        .map_err(|err| IpRetrieveError::ip_retrieve(err.to_string()))?;

    let text = resp
        .text()
        .await
        .map_err(|err| IpRetrieveError::ip_retrieve(err.to_string()))?;

    parse_ip_response(&text)
}

/// Parses an IP address out of an IP-echo service's HTTP response body.
///
/// Several of the upstream services append a trailing newline (and some surround the
/// address with whitespace), which `IpAddr::from_str` rejects verbatim. Trimming first
/// makes resolution robust to those harmless formatting differences instead of letting an
/// otherwise-valid fallback service fail. The trimmed text must still be exactly one IP
/// address — embedded whitespace or extra tokens are still rejected.
fn parse_ip_response(text: &str) -> Result<IpAddr, IpRetrieveError> {
    IpAddr::from_str(text.trim()).map_err(|err| IpRetrieveError::ip_retrieve(err.to_string()))
}

// --- Platform-specific internal IP resolution ---

#[cfg(not(target_family = "wasm"))]
mod native {
    use super::*;
    use std::str::FromStr;

    /// Gets the internal IP address using a UDP socket trick (native only)
    pub async fn get_internal_ip(ipv6: bool) -> Option<IpAddr> {
        if ipv6 {
            get_internal_ipv6().await
        } else {
            get_internal_ipv4().await
        }
    }

    /// Returns the internal ipv4 address of this node
    pub async fn get_internal_ipv4() -> Option<IpAddr> {
        let socket = citadel_io::tokio::net::UdpSocket::bind(addr("0.0.0.0:0")?)
            .await
            .ok()?;
        socket.connect(addr("8.8.8.8:80")?).await.ok()?;
        socket.local_addr().ok().map(|sck| sck.ip())
    }

    async fn get_internal_ipv6() -> Option<IpAddr> {
        let socket = citadel_io::tokio::net::UdpSocket::bind(addr("[::]:0")?)
            .await
            .ok()?;
        socket
            .connect(addr("[2001:4860:4860::8888]:80")?)
            .await
            .ok()?;
        socket.local_addr().ok().map(|sck| sck.ip())
    }

    fn addr(addr: &str) -> Option<std::net::SocketAddr> {
        std::net::SocketAddr::from_str(addr).ok()
    }
}

#[cfg(not(target_family = "wasm"))]
pub use native::{get_internal_ip, get_internal_ipv4};

#[cfg(not(target_family = "wasm"))]
async fn resolve_internal_ip(ipv6: bool) -> Option<IpAddr> {
    get_internal_ip(ipv6).await
}

#[cfg(target_family = "wasm")]
async fn resolve_internal_ip(_ipv6: bool) -> Option<IpAddr> {
    // Browser cannot discover LAN IP address; return localhost
    Some(IpAddr::from_str("127.0.0.1").unwrap())
}

/// Returns a default client
pub fn get_default_client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}

/// The default error type for this crate
pub type IpRetrieveError = citadel_io::NetworkError;

#[cfg(test)]
mod tests {
    use super::parse_ip_response;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_bare_ipv4() {
        assert_eq!(
            parse_ip_response("1.2.3.4").unwrap(),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn trims_trailing_newline() {
        // Some IP-echo services append a trailing '\n'; this previously broke parsing.
        assert_eq!(
            parse_ip_response("1.2.3.4\n").unwrap(),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn trims_surrounding_whitespace_and_crlf() {
        assert_eq!(
            parse_ip_response("  1.2.3.4  ").unwrap(),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(
            parse_ip_response("2001:db8::1\r\n").unwrap(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn rejects_garbage_and_embedded_tokens() {
        assert!(parse_ip_response("").is_err());
        assert!(parse_ip_response("not-an-ip").is_err());
        // Trimming must not turn a multi-token body into a valid parse.
        assert!(parse_ip_response("1.2.3.4 5.6.7.8").is_err());
        assert!(parse_ip_response("<html>error</html>").is_err());
    }
}

#[cfg(test)]
mod external_ipv6_family_tests {
    use super::only_ipv6;
    use std::net::IpAddr;
    use std::str::FromStr;

    /// The defect: a "v6" endpoint reached over IPv4 answers with an IPv4
    /// address, and storing it as `external_ipv6` makes
    /// `get_optimal_bind_socket` bind `[::]:0` on a host with no IPv6. The hole
    /// puncher then advertises an IPv6 candidate it has no IPv6 internal
    /// address to substitute for, and the peer cannot reach it. Observed in CI
    /// as `invalid remote address: [::]:47790` on a runner whose only internal
    /// address was `10.1.1.120`.
    #[test]
    fn an_ipv4_answer_is_not_an_external_ipv6_address() {
        assert_eq!(
            only_ipv6(IpAddr::from_str("172.208.127.86").unwrap()),
            None,
            "an IPv4 address was accepted as the external IPv6 address"
        );
    }

    #[test]
    fn a_real_ipv6_answer_is_kept() {
        let v6 = IpAddr::from_str("2001:db8::1").unwrap();
        assert_eq!(
            only_ipv6(v6),
            Some(v6),
            "a genuine IPv6 address was discarded"
        );
    }
}
