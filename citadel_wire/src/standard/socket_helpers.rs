//! Socket Creation and Configuration Utilities
//!
//! This module provides a comprehensive set of utilities for creating and configuring
//! network sockets with proper settings for NAT traversal and peer-to-peer communication.
//! It handles platform-specific socket options and provides a unified interface for both
//! TCP and UDP protocols.
//!
//! # Features
//!
//! - TCP and UDP socket creation with proper options
//! - Platform-specific socket configuration handling
//! - IPv4 and IPv6 support with automatic mapping
//! - Socket reuse options for NAT traversal
//! - Connection timeout management
//! - Backlog configuration for TCP listeners
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::socket_helpers;
//! use std::net::SocketAddr;
//! use std::time::Duration;
//!
//! async fn setup_sockets() -> Result<(), anyhow::Error> {
//!     let addr: SocketAddr = "127.0.0.1:8080".parse()?;
//!
//!     // Create UDP socket with address reuse
//!     let udp = socket_helpers::get_udp_socket(addr)?;
//!
//!     // Create TCP listener with default options
//!     let tcp = socket_helpers::get_tcp_listener(addr)?;
//!
//!     // Create TCP client with timeout
//!     let stream = socket_helpers::get_tcp_stream(addr, Duration::from_secs(5)).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//!
//! - Socket reuse options are essential for NAT traversal
//! - Platform-specific behaviors are handled automatically
//! - IPv6 support requires system configuration
//! - TCP listeners have configurable connection backlogs
//! - Default timeouts are recommended for reliability
//!
//! # Related Components
//!
//! - [`crate::standard::nat_identification`] - NAT behavior analysis
//! - [`crate::udp_traversal`] - UDP hole punching implementation
//! - [`crate::standard::upnp_handler`] - UPnP port forwarding
//! - [`crate::error::FirewallError`] - Network error handling
//!

use citadel_io::tokio::net::{TcpListener, TcpStream, UdpSocket};
use socket2::{Domain, SockAddr, Socket, Type};
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::time::Duration;

fn get_udp_socket_builder(domain: Domain) -> Result<Socket, anyhow::Error> {
    let socket = socket2::Socket::new(domain, Type::DGRAM, None)?;

    // On Windows, disable the behavior where ICMP "port unreachable" messages
    // cause WSAECONNRESET (10054) errors on UDP sockets. This is a well-known
    // Windows-specific issue that can cause spurious connection reset errors
    // during NAT traversal and hole punching.
    #[cfg(windows)]
    {
        disable_windows_udp_connreset(&socket)?;
    }

    Ok(socket)
}

/// Disables Windows-specific behavior where ICMP "port unreachable" messages
/// cause WSAECONNRESET (10054) errors on subsequent UDP recv calls.
///
/// This is critical for NAT traversal and hole punching where ICMP messages
/// from failed connection attempts are expected and should be ignored.
///
/// See: <https://docs.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls>
#[cfg(windows)]
#[allow(unsafe_code)]
fn disable_windows_udp_connreset(socket: &Socket) -> Result<(), anyhow::Error> {
    use std::os::windows::io::AsRawSocket;

    // SIO_UDP_CONNRESET = 0x9800000C
    // When set to FALSE (0), this disables the connection reset behavior
    const SIO_UDP_CONNRESET: u32 = 0x9800000C;
    let disable: u32 = 0; // FALSE = disable connection reset reporting

    // SAFETY: We're calling WSAIoctl with valid parameters on a valid socket.
    // The socket is owned by us and the ioctl is a well-documented Windows API.
    let result = unsafe {
        let mut bytes_returned: u32 = 0;
        windows_sys::Win32::Networking::WinSock::WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            std::ptr::addr_of!(disable) as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };

    if result != 0 {
        let err = std::io::Error::last_os_error();
        log::warn!(target: "citadel", "Failed to set SIO_UDP_CONNRESET: {err}");
        // Don't fail socket creation, just log the warning
        // The socket will still work, just may have spurious reset errors
    } else {
        log::trace!(target: "citadel", "Successfully disabled UDP connection reset reporting");
    }

    Ok(())
}

fn get_tcp_socket_builder(domain: Domain) -> Result<Socket, anyhow::Error> {
    Ok(socket2::Socket::new(domain, Type::STREAM, None)?)
}

fn setup_base_socket(addr: SocketAddr, socket: &Socket, reuse: bool) -> Result<(), anyhow::Error> {
    if reuse {
        socket.set_reuse_address(true)?;

        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        {
            socket.set_reuse_port(true)?;
        }
    }

    socket.set_nonblocking(true)?;

    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }

    Ok(())
}

fn setup_bind(addr: SocketAddr, socket: &Socket, reuse: bool) -> Result<(), anyhow::Error> {
    setup_base_socket(addr, socket, reuse)?;
    socket.bind(&SockAddr::from(addr))?;

    Ok(())
}

async fn setup_connect(
    connect_addr: SocketAddr,
    socket: Socket,
    timeout: Duration,
    reuse: bool,
) -> Result<TcpStream, anyhow::Error> {
    setup_base_socket(connect_addr, &socket, reuse)?;
    let socket = citadel_io::tokio::net::TcpSocket::from_std_stream(socket.into());
    Ok(citadel_io::tokio::time::timeout(timeout, socket.connect(connect_addr)).await??)
}

fn get_udp_socket_inner<T: std::net::ToSocketAddrs>(
    addr: T,
    reuse: bool,
) -> Result<UdpSocket, anyhow::Error> {
    let addr: SocketAddr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::Error::msg("Bad socket addr"))?;

    let addr = localhost_testing_addr_fix(addr);

    log::trace!(target: "citadel", "[Socket helper] Getting UDP (reuse={}) socket @ {:?} ...", reuse, &addr);
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = get_udp_socket_builder(domain)?;
    setup_bind(addr, &socket, reuse)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket = citadel_io::tokio::net::UdpSocket::from_std(std_socket)?;
    Ok(tokio_socket)
}

fn localhost_testing_addr_fix(addr: SocketAddr) -> SocketAddr {
    // In localhost-testing mode, bind to 127.0.0.1 instead of 0.0.0.0.
    // This ensures socket.local_addr() returns 127.0.0.1 which peers can actually send to.
    // Without this, macOS fails with "No route to host" when sending to 0.0.0.0.
    if cfg!(feature = "localhost-testing") {
        log::trace!(target: "citadel", "Localhost testing enabled, binding to localhost instead of {addr}");
        if addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), addr.port())
        } else {
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), addr.port())
        }
    } else {
        addr
    }
}

fn get_tcp_listener_inner<T: std::net::ToSocketAddrs>(
    addr: T,
    reuse: bool,
) -> Result<TcpListener, anyhow::Error> {
    let addr: SocketAddr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::Error::msg("Bad socket addr"))?;

    let addr = localhost_testing_addr_fix(addr);

    log::trace!(target: "citadel", "[Socket helper] Getting TCP listener (reuse={}) socket @ {:?} ...", reuse, &addr);

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = get_tcp_socket_builder(domain)?;
    setup_bind(addr, &socket, reuse)?;
    socket.listen(1024)?;
    let std_tcp_socket: std::net::TcpListener = socket.into();
    Ok(citadel_io::tokio::net::TcpListener::from_std(
        std_tcp_socket,
    )?)
}

async fn get_tcp_stream_inner<T: std::net::ToSocketAddrs>(
    addr: T,
    timeout: Duration,
    reuse: bool,
) -> Result<TcpStream, anyhow::Error> {
    let addr: SocketAddr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::Error::msg("Bad socket addr"))?;
    log::trace!(target: "citadel", "[Socket helper] Getting TCP connect (reuse={}) socket to {:?} ...", reuse, &addr);
    //return Ok(citadel_io::TcpStream::connect(addr).await?)
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = get_tcp_socket_builder(domain)?;
    setup_connect(addr, socket, timeout, true).await
}

pub fn get_udp_socket<T: std::net::ToSocketAddrs>(addr: T) -> Result<UdpSocket, anyhow::Error> {
    get_udp_socket_inner(addr, false)
}

/// `backlog`: the max number of unprocessed TCP connections
pub fn get_tcp_listener<T: std::net::ToSocketAddrs>(addr: T) -> Result<TcpListener, anyhow::Error> {
    get_tcp_listener_inner(addr, false)
}

pub async fn get_tcp_stream<T: std::net::ToSocketAddrs>(
    addr: T,
    timeout: Duration,
) -> Result<TcpStream, anyhow::Error> {
    get_tcp_stream_inner(addr, timeout, false).await
}

pub fn is_ipv6_enabled() -> bool {
    // this is a bit hacky, but, should prevent pipelines from failing
    // if runners don't have ipv6 compat
    if let Ok(sck) = std::net::TcpListener::bind("[::]:0") {
        sck.local_addr().map(|r| r.is_ipv6()).unwrap_or(false)
    } else {
        false
    }
}

// ensures ipv4 addresses are in terms of v6
pub fn ensure_ipv6(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

#[cfg(test)]
mod tests {
    use crate::socket_helpers::{
        get_tcp_listener, get_tcp_stream, get_udp_socket, is_ipv6_enabled,
    };
    use citadel_io::tokio;
    use citadel_io::tokio::io::{AsyncReadExt, AsyncWriteExt};
    use rstest::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_millis(2000);

    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[trace]
    #[tokio::test]
    async fn test_tcp(#[case] addr: SocketAddr) -> std::io::Result<()> {
        citadel_logging::setup_log();
        if addr.is_ipv6() && !is_ipv6_enabled() {
            log::trace!(target: "citadel", "Skipping IPv6 test since IPv6 is not enabled");
            return Ok(());
        }
        let server = get_tcp_listener(addr).unwrap();
        let addr = server.local_addr().unwrap();

        let server = citadel_io::tokio::task::spawn(async move {
            log::trace!(target: "citadel", "Starting server @ {addr:?}");
            let (mut conn, addr) = server.accept().await.unwrap();
            log::trace!(target: "citadel", "RECV {:?} from {:?}", &conn, addr);
            let buf = &mut [0u8; 3];
            conn.read_exact(buf as &mut [u8]).await.unwrap();
            assert_eq!(buf, &[1, 2, 3]);
        });

        let client = citadel_io::tokio::task::spawn(async move {
            let mut client = get_tcp_stream(addr, TIMEOUT).await.unwrap();
            client.write_all(&[1, 2, 3]).await.unwrap();
        });

        let (r0, r1) = citadel_io::tokio::join!(server, client);
        Ok(r0.and(r1)?)
    }

    #[rstest]
    #[case("127.0.0.1:0")]
    #[case("[::1]:0")]
    #[trace]
    #[tokio::test]
    async fn test_udp(#[case] addr: SocketAddr) -> Result<(), anyhow::Error> {
        citadel_logging::setup_log();
        if addr.is_ipv6() && !is_ipv6_enabled() {
            log::trace!(target: "citadel", "Skipping IPv6 test since IPv6 is not enabled");
            return Ok(());
        }
        let server = get_udp_socket(addr).unwrap();
        let addr = server.local_addr().unwrap();
        let (ready_tx, ready_rx) = citadel_io::tokio::sync::oneshot::channel();

        let server = citadel_io::tokio::task::spawn(async move {
            log::trace!(target: "citadel", "Starting server @ {addr:?}");
            let buf = &mut [0u8; 3];
            ready_tx.send(()).unwrap();
            server.recv(buf as &mut [u8]).await?;
            assert_eq!(buf, &[1, 2, 3]);
            Ok(()) as Result<(), anyhow::Error>
        });

        let client_bind_addr = if addr.is_ipv6() {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        };

        let client = citadel_io::tokio::task::spawn(async move {
            let client = get_udp_socket(client_bind_addr)?;
            ready_rx.await?;
            client.send_to(&[1, 2, 3], addr).await?;
            Ok(()) as Result<(), anyhow::Error>
        });

        let (r0, r1) = citadel_io::tokio::try_join!(server, client)?;
        log::trace!(target: "citadel", "Done with UDP test {addr:?}");
        r0.and(r1)
    }
}
