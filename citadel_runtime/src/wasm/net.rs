use crate::Error;
use std::net::ToSocketAddrs;

pub struct UdpSocket {
    inner: wasmedge_wasi_socket::UdpSocket
}

impl UdpSocket {
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error> {
        let inner = wasmedge_wasi_socket::UdpSocket::bind(addr)?;
        Ok(UdpSocket { inner })
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::IoError(value)
    }
}