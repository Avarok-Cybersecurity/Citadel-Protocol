use std::fmt::{Debug, Formatter};
use std::net::{SocketAddr, ToSocketAddrs};
use ws_stream_wasm::WsMeta;

pub type TcpStream = tokio::net::TcpStream;
pub type UdpSocket = UdpSocketImpl;
pub type TcpListener = tokio::net::TcpListener;

pub struct UdpSocketImpl {
    #[allow(dead_code)]
    inner: ws_stream_wasm::WsStreamIo,
    #[allow(dead_code)]
    meta: WsMeta,
}

impl UdpSocketImpl {
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let addr: SocketAddr = addr.to_socket_addrs()?.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "No addrs specified",
        ))?;
        let (meta, stream) = ws_stream_wasm::WsMeta::connect(addr.to_string(), None)
            .await
            .map_err(ws_to_io)?;
        let inner = ws_stream_wasm::WsStreamIo::new(stream);
        Ok(UdpSocketImpl { inner, meta })
    }
}

fn ws_to_io(err: ws_stream_wasm::WsErr) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", err))
}

impl Debug for UdpSocketImpl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let url = self.meta.url();
        write!(f, "[WASM socket] Connected to: {url}")
    }
}
