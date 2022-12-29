use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Given an ip bind addr, finds an open socket at that ip addr
pub fn get_unused_udp_socket_at_bind_ip(bind_addr: IpAddr) -> std::io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind((bind_addr, 0))?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

fn get_udp_socket_builder(domain: Domain) -> Result<Socket, anyhow::Error> {
    Ok(socket2::Socket::new(
        domain,
        Type::DGRAM,
        Some(Protocol::UDP),
    )?)
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
    let socket = tokio::net::TcpSocket::from_std_stream(socket.into());
    Ok(tokio::time::timeout(timeout, socket.connect(connect_addr)).await??)
}

fn get_udp_socket_inner<T: std::net::ToSocketAddrs>(
    addr: T,
    reuse: bool,
) -> Result<UdpSocket, anyhow::Error> {
    let addr: SocketAddr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::Error::msg("Bad socket addr"))?;
    log::trace!(target: "citadel", "[Socket helper] Getting UDP (reuse={}) socket @ {:?} ...", reuse, &addr);
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = get_udp_socket_builder(domain)?;
    setup_bind(addr, &socket, reuse)?;

    Ok(tokio::net::UdpSocket::from_std(socket.into())?)
}

fn get_tcp_listener_inner<T: std::net::ToSocketAddrs>(
    addr: T,
    reuse: bool,
) -> Result<TcpListener, anyhow::Error> {
    let addr: SocketAddr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::Error::msg("Bad socket addr"))?;
    log::trace!(target: "citadel", "[Socket helper] Getting TCP listener (reuse={}) socket @ {:?} ...", reuse, &addr);
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = get_tcp_socket_builder(domain)?;
    setup_bind(addr, &socket, reuse)?;

    Ok(tokio::net::TcpSocket::from_std_stream(socket.into()).listen(1024)?)
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
    log::trace!(target: "citadel", "[Socket helper] Getting TCP connect (reuse={}) socket @ {:?} ...", reuse, &addr);
    //return Ok(tokio::net::TcpStream::connect(addr).await?)
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = get_tcp_socket_builder(domain)?;
    setup_connect(addr, socket, timeout, true).await
}

pub fn get_reuse_udp_socket<T: std::net::ToSocketAddrs>(
    addr: T,
) -> Result<UdpSocket, anyhow::Error> {
    get_udp_socket_inner(addr, true)
}

pub fn get_reuse_tcp_listener<T: std::net::ToSocketAddrs>(
    addr: T,
) -> Result<TcpListener, anyhow::Error> {
    get_tcp_listener_inner(addr, true)
}

pub async fn get_reuse_tcp_stream<T: std::net::ToSocketAddrs>(
    addr: T,
    timeout: Duration,
) -> Result<TcpStream, anyhow::Error> {
    get_tcp_stream_inner(addr, timeout, true).await
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

#[allow(dead_code)]
async fn asyncify<F, O>(fx: F) -> Result<O, anyhow::Error>
where
    F: FnOnce() -> O,
    F: Send + 'static,
    O: Send + 'static,
{
    Ok(tokio::task::spawn_blocking(fx).await?)
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
    use rstest::*;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

        let server = tokio::spawn(async move {
            log::trace!(target: "citadel", "Starting server @ {:?}", addr);
            let (mut conn, addr) = server.accept().await.unwrap();
            log::trace!(target: "citadel", "RECV {:?} from {:?}", &conn, addr);
            let buf = &mut [0u8; 3];
            conn.read_exact(buf as &mut [u8]).await.unwrap();
            assert_eq!(buf, &[1, 2, 3]);
        });

        let client = tokio::spawn(async move {
            let mut client = get_tcp_stream(addr, TIMEOUT).await.unwrap();
            client.write_all(&[1, 2, 3]).await.unwrap();
        });

        let (r0, r1) = tokio::join!(server, client);
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
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        let server = tokio::spawn(async move {
            log::trace!(target: "citadel", "Starting server @ {:?}", addr);
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

        let client = tokio::spawn(async move {
            let client = get_udp_socket(client_bind_addr)?;
            ready_rx.await?;
            client.send_to(&[1, 2, 3], addr).await?;
            Ok(()) as Result<(), anyhow::Error>
        });

        let (r0, r1) = tokio::try_join!(server, client)?;
        log::trace!(target: "citadel", "Done with UDP test {:?}", addr);
        r0.and(r1)
    }
}
