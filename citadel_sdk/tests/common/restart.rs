//! A server that restarts in place on the address it had.

use citadel_io::tokio;
use std::net::SocketAddr;

/// A listener with SO_REUSEADDR, for BOTH servers. On Linux a socket may bind a port others
/// hold only if every socket there set SO_REUSEADDR -- and the old server's accepted client
/// sockets inherit its listener's options. v1 was made with `get_tcp_listener` (no reuse), so
/// its live and TIME_WAIT connections kept v2 out ("Address already in use (os error 98)",
/// CI on PR #318) however long v2 waited. A server that restarts in place must reuse from its
/// first bind, as any real one does.
pub fn listener_at(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

/// v2 on v1's address. Retried, bounded, only on AddrInUse: v1's listening socket goes away
/// with its task, asynchronously.
pub fn rebind(addr: SocketAddr) -> tokio::net::TcpListener {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match listener_at(addr) {
            Ok(listener) => return listener,
            Err(err)
                if err.kind() == std::io::ErrorKind::AddrInUse
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(err) => panic!("could not rebind {addr} for server v2: {err}"),
        }
    }
}
