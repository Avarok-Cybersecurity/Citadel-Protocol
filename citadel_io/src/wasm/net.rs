use std::net::{SocketAddr, ToSocketAddrs};
use ws_stream_wasm::WsMeta;

pub type TcpStream = ws_stream_wasm::WsStreamIo;
pub type UdpSocketType = ws_stream_wasm::WsStreamIo;
pub type TcpListener = ws_stream_wasm::WsStreamIo;

pub struct UdpSocket {
    inner: UdpSocketType,
    meta: WsMeta,
}

impl UdpSocket {
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let addr: SocketAddr = addr.to_socket_addrs()?.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "No addrs specified",
        ))?;
        let (meta, stream) = ws_stream_wasm::WsMeta::connect(addr.to_string(), None)
            .await
            .map_err(ws_to_io)?;
        let inner = UdpSocketType::new(stream);
        Ok(UdpSocket { inner, meta })
    }
}

fn ws_to_io(err: ws_stream_wasm::WsErr) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", err))
}
