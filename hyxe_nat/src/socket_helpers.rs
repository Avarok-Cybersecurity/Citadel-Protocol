use tokio::net::{UdpSocket, TcpStream, TcpListener};
use std::net::SocketAddr;
use std::time::Duration;

pub fn get_reuse_udp_socket<T: std::net::ToSocketAddrs>(addr: T) -> Result<UdpSocket, anyhow::Error> {
    let addr: SocketAddr = addr.to_socket_addrs()?.next().ok_or(anyhow::Error::msg("No sockets"))?;
    log::info!("Getting UDP reuse socket @ {:?} ...", &addr);
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        {
            use net2::unix::UnixUdpBuilderExt;
            if addr.is_ipv4() {
                let builder = net2::UdpBuilder::new_v4()?;
                Ok(builder.reuse_address(true)?.reuse_port(true)?.bind(addr).and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::UdpSocket::from_std(r)
                })?)
            } else {
                let builder = net2::UdpBuilder::new_v6()?;
                Ok(builder.only_v6(false)?.reuse_address(true)?.reuse_port(true)?.bind(addr).and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::UdpSocket::from_std(r)
                })?)
            }
        }
    #[cfg(not(all(unix, not(any(target_os = "solaris", target_os = "illumos")))))]
        {
            if addr.is_ipv4() {
                let builder = net2::UdpBuilder::new_v4()?;
                Ok(builder.reuse_address(true)?.bind(addr).and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::UdpSocket::from_std(r)
                })?)
            } else {
                let builder = net2::UdpBuilder::new_v6()?;
                Ok(builder.only_v6(false)?.reuse_address(true)?.bind(addr).and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::UdpSocket::from_std(r)
                })?)
            }
        }
}

/// `backlog`: the max number of unprocessed TCP connections
pub fn get_reuse_tcp_listener<T: std::net::ToSocketAddrs>(addr: T,  backlog: i32) -> Result<TcpListener, anyhow::Error> {
    let addr: SocketAddr = addr.to_socket_addrs()?.next().ok_or(anyhow::Error::msg("No socket addrs"))?;

    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        {
            use net2::unix::UnixTcpBuilderExt;

            if addr.is_ipv4() {
                let builder = net2::TcpBuilder::new_v4()?;
                Ok(builder.reuse_address(true)?.reuse_port(true)?.bind(addr)?.listen(backlog).and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::TcpListener::from_std(r)
                })?)
            } else {
                let builder = net2::TcpBuilder::new_v6()?;
                Ok(builder.only_v6(false)?.reuse_address(true)?.reuse_port(true)?.bind(addr)?.listen(backlog).and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::TcpListener::from_std(r)
                })?)
            }
        }
    #[cfg(not(all(unix, not(any(target_os = "solaris", target_os = "illumos")))))]
        {
            if addr.is_ipv4() {
                let builder = net2::TcpBuilder::new_v4()?;
                Ok(builder.reuse_address(true)?.bind(addr)?.listen(backlog).and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::TcpListener::from_std(r)
                })?)
            } else {
                let builder = net2::TcpBuilder::new_v6()?;
                Ok(builder.only_v6(false)?.reuse_address(true)?.bind(addr)?.listen(backlog).and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::TcpListener::from_std(r)
                })?)
            }
        }
}

pub async fn get_reuse_tcp_stream<T: std::net::ToSocketAddrs>(addr: T, timeout: Duration) -> Result<TcpStream, anyhow::Error> {
    let addr: SocketAddr = addr.to_socket_addrs()?.next().ok_or(anyhow::Error::msg("No socket addrs"))?;

    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        {
            use net2::unix::UnixTcpBuilderExt;

            if addr.is_ipv4() {
                Ok(asyncify(move ||net2::TcpBuilder::new_v4()?.reuse_address(true)?.reuse_port(true)?.connect(addr), timeout).await?.and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::TcpStream::from_std(r)
                })?)
            } else {
                Ok(asyncify(move ||net2::TcpBuilder::new_v6()?.only_v6(false)?.reuse_address(true)?.reuse_port(true)?.connect(addr), timeout).await?.and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::TcpStream::from_std(r)
                })?)
            }
        }
    #[cfg(not(all(unix, not(any(target_os = "solaris", target_os = "illumos")))))]
        {
            if addr.is_ipv4() {
                Ok(asyncify(move ||net2::TcpBuilder::new_v4()?.reuse_address(true)?.connect(addr), timeout).await?.and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::TcpStream::from_std(r)
                })?)
            } else {
                Ok(asyncify(move ||net2::TcpBuilder::new_v6()?.only_v6(false)?.reuse_address(true)?.connect(addr), timeout).await?.and_then(|r| {
                    r.set_nonblocking(true)?;
                    tokio::net::TcpStream::from_std(r)
                })?)
            }
        }
}

pub fn get_udp_socket<T: std::net::ToSocketAddrs>(addr: T) -> Result<UdpSocket, anyhow::Error> {
    let addr: SocketAddr = addr.to_socket_addrs()?.next().ok_or(anyhow::Error::msg("No sockets"))?;
    log::info!("Getting UDP socket @ {:?} ...", &addr);
    if addr.is_ipv4() {
        let builder = net2::UdpBuilder::new_v4()?;
        Ok(builder.bind(addr).and_then(|r| {
            r.set_nonblocking(true)?;
            tokio::net::UdpSocket::from_std(r)
        })?)
    } else {
        let builder = net2::UdpBuilder::new_v6()?;
        Ok(builder.only_v6(false)?.bind(addr).and_then(|r| {
            r.set_nonblocking(true)?;
            tokio::net::UdpSocket::from_std(r)
        })?)
    }
}

/// `backlog`: the max number of unprocessed TCP connections
pub fn get_tcp_listener<T: std::net::ToSocketAddrs>(addr: T,  backlog: i32) -> Result<TcpListener, anyhow::Error> {
    let addr: SocketAddr = addr.to_socket_addrs()?.next().ok_or(anyhow::Error::msg("No socket addrs"))?;
    if addr.is_ipv4() {
        let builder = net2::TcpBuilder::new_v4()?;
        Ok(builder.bind(addr)?.listen(backlog).and_then(|r| {
            r.set_nonblocking(true)?;
            tokio::net::TcpListener::from_std(r)
        })?)
    } else {
        let builder = net2::TcpBuilder::new_v6()?;
        Ok(builder.only_v6(false)?.bind(addr)?.listen(backlog).and_then(|r| {
            r.set_nonblocking(true)?;
            tokio::net::TcpListener::from_std(r)
        })?)
    }
}

pub async fn get_tcp_stream<T: std::net::ToSocketAddrs>(addr: T, timeout: Duration) -> Result<TcpStream, anyhow::Error> {
    let addr: SocketAddr = addr.to_socket_addrs()?.next().ok_or(anyhow::Error::msg("No socket addrs"))?;

    if addr.is_ipv4() {
        Ok(asyncify(move ||net2::TcpBuilder::new_v4()?.connect(addr), timeout).await?.and_then(|r| {
            r.set_nonblocking(true)?;
            tokio::net::TcpStream::from_std(r)
        })?)
    } else {
        Ok(asyncify(move ||net2::TcpBuilder::new_v6()?.only_v6(false)?.connect(addr), timeout).await?.and_then(|r| {
            r.set_nonblocking(true)?;
            tokio::net::TcpStream::from_std(r)
        })?)
    }
}

async fn asyncify<F, O>(fx: F, timeout: Duration) -> Result<O, anyhow::Error>
    where F: FnOnce() -> O,
            F: Send + 'static,
            O: Send + 'static {
    Ok(tokio::time::timeout(timeout, tokio::task::spawn_blocking(move ||fx())).await??)
}